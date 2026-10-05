# frozen_string_literal: true

require "open3"
require "json"
require "tmpdir"
require "socket"
require "yaml"

RSpec.describe "bin/lictor" do
  let(:exe) { File.expand_path("../bin/lictor", __dir__) }
  let(:facts_text) do
    "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\nplt(\"system\").\n" \
      "gadget(\"pop_rdi_ret\", 1).\nvuln_hint(\"unsafe_func:gets\").\n"
  end

  it "emits service candidates from an nmap XML scan" do
    xml = File.expand_path("fixtures/nmap_scan.xml", __dir__)
    out, _err, status = Open3.capture3(exe, "recon", xml)
    expect(status.exitstatus).to eq(0)
    expect(out).to include("192.168.56.10:22")
    expect(out).to include("192.168.56.11:21")
    expect(out).not_to include("192.168.56.10:4444") # closed port
  end

  it "hands off the decision with a recipe and trails it " do
    dir = Dir.mktmpdir
    path = File.join(dir, "target.facts")
    File.write(path, facts_text)
    out, _err, status = Open3.capture3(exe, "plan", path,
      "-t", File.join(dir, "trail.jsonl"))
    expect(status.exitstatus).to eq(0)
    expect(out).to include("handoff")
    expect(out).to include("selected:   ret2plt")
    expect(out).to include("ronin-exploits")
    expect(JSON.parse(File.read(File.join(dir, "trail.jsonl")))).to have_key("selected")
  end

  it "has no consent flag anywhere" do
    out, _err, _status = Open3.capture3(exe, "--help")
    expect(out).not_to include("i-am-authorized")
  end
end

RSpec.describe "lictor suggest" do
  let(:dir) { Dir.mktmpdir }
  let(:trail) { File.join(dir, "t.jsonl") }

  it "merges suggested facts, prints the delta and trails the suggestion" do
    facts = File.join(dir, "target.facts")
    File.write(facts, "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\n")
    out, _err, status = Open3.capture3(File.expand_path("../bin/lictor", __dir__),
      "suggest", facts, "plt(\"system\").\nvuln_hint(\"unsafe_func:gets\").\n", "-t", trail)
    expect(status.exitstatus).to eq(0)
    expect(out).to include("added:")
    expect(out).to include("ret2plt")
    event = JSON.parse(File.readlines(trail).last)
    expect(event["type"]).to eq("suggest")
  end

  it "refuses off-schema suggestions loudly" do
    facts = File.join(dir, "target.facts")
    File.write(facts, "nx(\"true\").\n")
    _out, err, status = Open3.capture3(File.expand_path("../bin/lictor", __dir__),
      "suggest", facts, "applicable(ret2plt).\n", "-t", File.join(dir, "t.jsonl"))
    expect(status.exitstatus).to eq(1)
    expect(err).to include("unknown predicate")
  end
end

RSpec.describe "lictor exploit scaffold" do
  let(:dir) { Dir.mktmpdir }
  let(:trail) { File.join(dir, "t.jsonl") }
  let(:binary) do
    builder = ["../../augure/profiler/spec/support/binary_builder.rb",
      "../augure/profiler/spec/support/binary_builder.rb"]
      .map { |p| File.expand_path(p, __dir__) }
      .find { |p| File.file?(p) }
    require_relative builder
    ProfilerBinaryBuilder.vulnerable
  end

  it "drafts a ronin exploit carrying the measured constants" do
    facts = File.join(dir, "target.facts")
    File.write(facts, "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\n" \
      "win_symbol(\"win\", 4196182).\ngadget(\"ret_align\", 4196100).\n")
    repo = File.join(dir, "ronin-repo", "exploits")
    FileUtils.mkdir_p(repo)
    _out, _err, status = Open3.capture3(File.expand_path("../bin/lictor", __dir__),
      "exploit", "scaffold", "ret2func", binary, "--facts", facts,
      "--repo-dir", repo, "--author", "tester", "-t", trail)
    expect(status.exitstatus).to eq(0)
    file = Dir.children(repo).first
    expect(file).to match(/\Alab_ret2func_001\.rb\z/)
    content = File.read(File.join(repo, file))
    expect(content).to include("MEASURED (static-frame)")
    expect(content).to include("win_symbol:win@4196182")
    expect(content).to include('register "lab_ret2func_001"')
    event = JSON.parse(File.readlines(trail).last)
    expect(event["type"]).to eq("scaffold")
  end

  it "indexes a second scaffold instead of overwriting" do
    facts = File.join(dir, "target.facts")
    File.write(facts, "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\n" \
      "win_symbol(\"win\", 4196182).\ngadget(\"ret_align\", 4196100).\n")
    repo = File.join(dir, "ronin-repo", "exploits")
    FileUtils.mkdir_p(repo)
    File.write(File.join(repo, "lab_ret2func_001.rb"), "# exists")
    _out, _err, status = Open3.capture3(File.expand_path("../bin/lictor", __dir__),
      "exploit", "scaffold", "ret2func", binary, "--facts", facts,
      "--repo-dir", repo, "-t", trail)
    expect(status.exitstatus).to eq(0)
    expect(Dir.children(repo)).to include("lab_ret2func_002.rb")
  end
end

RSpec.describe "lictor draft" do
  let(:dir) { Dir.mktmpdir }
  let(:trail) { File.join(dir, "t.jsonl") }
  let(:binary) do
    builder = ["../../augure/profiler/spec/support/binary_builder.rb",
      "../augure/profiler/spec/support/binary_builder.rb"]
      .map { |p| File.expand_path(p, __dir__) }
      .find { |p| File.file?(p) }
    require_relative builder
    ProfilerBinaryBuilder.vulnerable
  end

  it "drafts a pack in staging when nothing applies, validated by the armor" do
    facts = File.join(dir, "exotic.facts")
    File.write(facts, "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\n" \
      "allocator(\"tcache\").\nglibc_minor(39).\nseccomp(\"true\").\n")
    staging = File.join(dir, "staging")
    _out, err, status = Open3.capture3(File.expand_path("../bin/lictor", __dir__),
      "draft", facts, binary, "--repo-dir", staging, "-t", trail)
    expect(status.exitstatus).to eq(0), err
    file = Dir.children(staging).first
    expect(file).to match(/\Aautodraft_strcpy\.yml\z/)
    event = JSON.parse(File.readlines(trail).last)
    expect(event["type"]).to eq("pack_draft")
    expect(event["status"]).to eq("valid")
  end

  it "says so instead of drafting when built-ins cover the facts" do
    facts = File.join(dir, "covered.facts")
    File.write(facts, "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\n" \
      "win_symbol(\"win\", 4196182).\nvuln_hint(\"unsafe_func:strcpy\").\ntarget_function(\"true\").\n")
    staging = File.join(dir, "staging2")
    _out, err, status = Open3.capture3(File.expand_path("../bin/lictor", __dir__),
      "draft", facts, binary, "--repo-dir", staging, "-t", trail)
    expect(status.exitstatus).to eq(1)
    expect(err).to include("already cover")
  end
end

RSpec.describe "lictor harvest" do
  let(:dir) { Dir.mktmpdir }
  let(:trail) { File.join(dir, "t.jsonl") }

  it "turns the banner into leaked_address facts" do
    facts = File.join(dir, "target.facts")
    File.write(facts, "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\n")
    out, _err, status = Open3.capture3(File.expand_path("../bin/lictor", __dir__),
      "harvest", "127.0.0.1:9999", "-t", trail)
    skip "the lab is down" unless status.exitstatus.zero?
    expect(out).to include("win")
    event = JSON.parse(File.readlines(trail).last)
    expect(event["type"]).to eq("harvest")
  end
end

RSpec.describe "the hostile-target defenses" do
  let(:dir) { Dir.mktmpdir }

  it "the scaffold refuses a technique that would carry code into the filename or the template" do
    facts = File.join(dir, "target.facts")
    File.write(facts, "nx(\"true\").\n")
    repo = File.join(dir, "repo")
    FileUtils.mkdir_p(repo)
    binary = ["../../augure/profiler/spec/support/binary_builder.rb",
      "../augure/profiler/spec/support/binary_builder.rb"]
      .map { |p| File.expand_path(p, __dir__) }
      .find { |p| File.file?(p) }
    require_relative binary
    bin = ProfilerBinaryBuilder.vulnerable
    _out, err, status = Open3.capture3(File.expand_path("../bin/lictor", __dir__),
      "exploit", "scaffold", "evil\nFile.write('pwned','x')", bin, "--facts", facts, "--repo-dir", repo, "-t", File.join(dir, "t.jsonl"))
    expect(status.exitstatus).to eq(1)
    expect(err).to include("[a-z0-9_]+")
    expect(Dir.children(repo)).to be_empty
  end

  it "build refuses a non-ELF binary before anything executes" do
    facts = File.join(dir, "target.facts")
    File.write(facts, "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\n" \
      "win_symbol(\"win\", 4196182).\ngadget(\"ret_align\", 4196100).\n" \
      "vuln_hint(\"unsafe_func:strcpy\").\ntarget_function(\"true\").\n")
    notelf = File.join(dir, "notelf")
    File.write(notelf, "just text")
    _out, err, status = Open3.capture3(File.expand_path("../bin/lictor", __dir__),
      "build", notelf, "--facts", facts, "-t", File.join(dir, "t.jsonl"))
    expect(status.exitstatus).to eq(1)
    expect(err).to include("not an ELF")
  end
end

RSpec.describe "lictor run auto-scaffold via the CLI" do
  let(:exe) { File.expand_path("../bin/lictor", __dir__) }

  it "forwards --bin and --repo-dir so the flagship feature actually runs" do
    dir = Dir.mktmpdir
    builder = ["../../augure/profiler/spec/support/binary_builder.rb",
      "../augure/profiler/spec/support/binary_builder.rb"]
      .map { |p| File.expand_path(p, __dir__) }
      .find { |p| File.file?(p) }
    require_relative builder
    binary = ProfilerBinaryBuilder.vulnerable
    repo = File.join(dir, "repo", "exploits")
    FileUtils.mkdir_p(repo)
    facts = File.join(dir, "target.facts")
    File.write(facts,
      "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\n" \
      "win_symbol(\"win\", 4196182).\ngadget(\"ret_align\", 4196100).\n" \
      "target_function(\"true\").\n")

    out, err, status = Open3.capture3(exe, "run", "192.168.56.10",
      "--facts", facts, "--bin", binary, "--repo-dir", repo,
      "-t", File.join(dir, "trail.jsonl"), "--max-attempts", "2")
    expect(status.exitstatus).to eq(0), "run failed: #{err[0, 200]}"
    expect(File.exist?(File.join(repo, "lab_ret2func_001.rb"))).to be(true),
      "the auto-scaffold never fired from the CLI: #{out[0,
        200]}"
    expect(File.read(File.join(dir, "trail.jsonl"))).to include('"scaffold"')
  end
end

RSpec.describe "the fact write-back" do
  let(:dir) { Dir.mktmpdir }
  let(:trail) { File.join(dir, "t.jsonl") }
  let(:exe) { File.expand_path("../bin/lictor", __dir__) }

  it "suggest -o writes the merged fact base - the enrichment loop closes" do
    base = File.join(dir, "base.facts")
    File.write(base, "nx(\"true\").\npie(\"false\").\n")
    merged = File.join(dir, "merged.facts")
    out, err, status = Open3.capture3(exe, "suggest", base, 'vuln("sof").', "-o", merged, "-t", trail)
    expect(status.exitstatus).to eq(0), "suggest failed: #{err[0, 150]}"
    body = File.read(merged)
    expect(body).to include('nx("true")')
    expect(body).to include('vuln("sof")')
    expect(out).to include("added")
  end

  it "harvest --facts appends the leaked addresses to the file" do
    server = TCPServer.new("127.0.0.1", 0)
    port = server.addr[1]
    t = Thread.new do
      cli = server.accept
      cli.write "win() at 0x401260\n"
      cli.close
    rescue
      nil
    end
    facts = File.join(dir, "target.facts")
    File.write(facts, "nx(\"true\").\n")
    out, err, status = Open3.capture3(exe, "harvest", "127.0.0.1:#{port}", "--facts", facts, "-t", trail)
    t.join(2)
    server.close
    expect(status.exitstatus).to eq(0), "harvest failed: #{err[0, 150]}"
    expect(File.read(facts)).to include('leaked_address("win", 4199008)')
    expect(out).to include("leaked")
  end
end

RSpec.describe "lictor target" do
  let(:exe) { File.expand_path("../bin/lictor", __dir__) }
  let(:dir) { Dir.mktmpdir }
  let(:trail) { File.join(dir, "t.jsonl") }

  it "add scaffolds the target dir + the registry" do
    out, err, status = Open3.capture3(exe, "target", "add", "web01", "10.0.0.5:9999",
      "--from", "http://10.0.0.5:8000/binary", "-t", trail, chdir: dir)
    expect(status.exitstatus).to eq(0), "target add failed: #{err[0, 150]}"
    expect(File.directory?(File.join(dir, "targets", "web01"))).to be(true)
    registry = YAML.safe_load_file(File.join(dir, "targets.yml"))
    expect(registry["web01"]["host"]).to eq("10.0.0.5:9999")
    expect(registry["web01"]["from"]).to eq("http://10.0.0.5:8000/binary")
    expect(out).to include("web01")
  end

  it "acquire --target scopes the state into the target dir" do
    Open3.capture3(exe, "target", "add", "web01", "127.0.0.1:9999",
      "-t", trail, chdir: dir)
    binary = ProfilerBinaryBuilder.vulnerable
    _, err, status = Open3.capture3(exe, "acquire", "web01", "--bin", binary,
      "--target", "web01", "-t", trail, chdir: dir)
    expect(status.exitstatus).to eq(0), "acquire --target failed: #{err[0, 200]}"
    expect(File.file?(File.join(dir, "targets", "web01", "target.facts"))).to be(true)
    expect(File.file?(File.join(dir, "target.facts"))).to be(false) # the CWD stays clean
  end

  it "plan --target reads the target's facts and writes the target's trail" do
    Open3.capture3(exe, "target", "add", "web01", "127.0.0.1:9999", "-t", trail, chdir: dir)
    binary = ProfilerBinaryBuilder.vulnerable
    Open3.capture3(exe, "acquire", "web01", "--bin", binary, "--target", "web01",
      "-t", trail, chdir: dir)
    out, err, status = Open3.capture3(exe, "plan", "--target", "web01", chdir: dir)
    expect(status.exitstatus).to eq(0), "plan --target failed: #{err[0, 200]}"
    expect(out).to include("selected")
    expect(File.file?(File.join(dir, "targets", "web01", "trail.jsonl"))).to be(true)
  end
end
