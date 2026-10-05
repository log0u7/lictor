# frozen_string_literal: true

require "lictor"
require "timeout"
require "tmpdir"

RSpec.describe Lictor::Executor do
  let(:recipe) do
    {technique: "ret2plt", runner: "ronin", mixin: "Binary",
     console: "ronin-exploits run <exploit-name-from-your-repos> --technique ret2plt"}
  end

  it "defaults to the manual executor (handoff stays the default)" do
    executor = described_class.resolve(:manual)
    expect(executor).to be_a(Lictor::ManualExecutor)
  end

  it "raises on an unknown executor" do
    expect { described_class.resolve(:telepathy) }
      .to raise_error(Lictor::ExecutorError, /unknown executor/)
  end
end

RSpec.describe Lictor::ManualExecutor do
  it "executes nothing and returns the handoff" do
    result = described_class.new.execute(
      target: "192.168.56.10",
      technique: "ret2plt",
      recipe: {console: "ronin-exploits run x --technique ret2plt"}
    )
    expect(result[:executed]).to be(false)
    expect(result[:success]).to be_nil
    expect(result[:handoff]).to include("ronin-exploits run x")
  end
end

RSpec.describe Lictor::RoninExecutor do
  let(:recipe) do
    {technique: "ret2plt", runner: "ronin", mixin: "Binary",
     console: "ronin-exploits run x --technique ret2plt"}
  end
  let(:stub_runner) do
    path = File.join(Dir.mktmpdir, "ronin-exploits")
    File.write(path, <<~SH)
      #!/bin/sh
      if [ "$1" = "list" ]; then
        echo "  lab_ret2plt_001"
        echo "  lab_srop_001"
        echo "  other_thing_002"
      elif [ "$1" = "run" ]; then
        # $2 = exploit name; --param host=X --param port=Y
        echo "exploit ran: $2 $3 $4 $5 $6 $7"
        exit 0
      fi
    SH
    File.chmod(0o755, path)
    path
  end

  it "discovers which installed exploits match the decided technique (naming convention)" do
    executor = described_class.new(runner: stub_runner)
    matches = executor.discover("ret2plt")
    expect(matches).to eq(["lab_ret2plt_001"])
  end

  it "returns [] when no repo exploit matches the technique" do
    executor = described_class.new(runner: stub_runner)
    expect(executor.discover("heap_tcache")).to eq([])
  end

  it "executes the matching exploit against the consented target" do
    executor = described_class.new(runner: stub_runner)
    result = executor.execute(target: "192.168.56.10:9999", technique: "ret2plt", recipe: recipe,
      exploit_name: "lab_ret2plt_001")
    expect(result[:executed]).to be(true)
    expect(result[:success]).to be(true)
    expect(result[:exploit]).to eq("lab_ret2plt_001")
  end

  it "auto-discovers the exploit when none is named" do
    executor = described_class.new(runner: stub_runner)
    result = executor.execute(target: "192.168.56.10:9999", technique: "srop", recipe: recipe)
    expect(result[:exploit]).to eq("lab_srop_001")
    expect(result[:executed]).to be(true)
  end

  it "returns an honest no-match instead of executing anything" do
    executor = described_class.new(runner: stub_runner)
    result = executor.execute(target: "192.168.56.10:9999", technique: "heap_tcache", recipe: recipe)
    expect(result[:executed]).to be(false)
    expect(result[:note]).to include("no heap_tcache exploit")
  end
end

RSpec.describe "the executor timeout" do
  it "kills a black-holed runner instead of hanging forever" do
    sleeper = File.join(Dir.mktmpdir, "sleep.sh")
    File.write(sleeper, "#!/bin/sh\nsleep 300\n")
    File.chmod(0o755, sleeper)
    exec = Lictor::Executor.resolve(:ronin)
    exec.instance_variable_set(:@runner, sleeper)
    expect {
      exec.execute(target: "127.0.0.1:9", technique: "x", recipe: {console: ""}, exploit_name: "whatever", timeout: 1)
    }.to raise_error(Lictor::ExecutorError)
  end
end

RSpec.describe "the executor reads the flag, not the exit code" do
  # the lab exploits raise when the flag does not come (the ronin exit
  # code is honest there) - but a "polite" exploit exits 0 on failure,
  # and an exploit that lands the flag after a caught cleanup exits
  # non-zero. The FLAG IN THE OUTPUT is the truth the operator cares
  # about; --flag-regex makes it the success oracle.
  let(:recipe) do
    {technique: "ret2func", runner: "ronin", mixin: "Binary",
     console: "ronin-exploits run x --technique ret2func"}
  end

  def runner(printing:, exit_code:)
    path = File.join(Dir.mktmpdir, "ronin-exploits")
    File.write(path, <<~SH)
      #!/bin/sh
      if [ "$1" = "list" ]; then
        echo "  lab_ret2func_001"
      elif [ "$1" = "run" ]; then
        echo "#{printing}"
        exit #{exit_code}
      fi
    SH
    File.chmod(0o755, path)
    path
  end

  it "a flag in the output succeeds even when the runner exits non-zero" do
    exec = Lictor::RoninExecutor.new(runner: runner(printing: "FLAG{the_flag}", exit_code: 1))
    result = exec.execute(target: "127.0.0.1:9999", technique: "ret2func", recipe: recipe,
      exploit_name: "lab_ret2func_001", flag_regex: "FLAG\\{[^}]+\\}")
    expect(result[:executed]).to be(true)
    expect(result[:success]).to be(true), "the flag came; the exit code must not lie about it"
    expect(result[:flag]).to eq("FLAG{the_flag}")
  end

  it "no flag in the output fails even when the runner exits zero" do
    exec = Lictor::RoninExecutor.new(runner: runner(printing: "all quiet", exit_code: 0))
    result = exec.execute(target: "127.0.0.1:9999", technique: "ret2func", recipe: recipe,
      exploit_name: "lab_ret2func_001", flag_regex: "FLAG\\{[^}]+\\}")
    expect(result[:success]).to be(false), "an exit code is not a flag"
  end

  it "without a flag regex the exit code stays the oracle (the honest fallback)" do
    exec = Lictor::RoninExecutor.new(runner: runner(printing: "all quiet", exit_code: 0))
    result = exec.execute(target: "127.0.0.1:9999", technique: "ret2func", recipe: recipe,
      exploit_name: "lab_ret2func_001")
    expect(result[:success]).to be(true)
  end
end
