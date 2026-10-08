# frozen_string_literal: true

require "lictor"
require "json"
require "tmpdir"

RSpec.describe Lictor::Run do
  let(:dir) { Dir.mktmpdir }
  let(:trail_path) { File.join(dir, "t.jsonl") }
  let(:trail) { Lictor::Trail.new(trail_path) }
  let(:facts_text) do
    "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\nplt(\"system\").\n" \
      "gadget(\"pop_rdi_ret\", 1).\nvuln_hint(\"unsafe_func:gets\").\n"
  end
  let(:stub_executor) do
    Class.new do
      def initialize(results)
        @results = results
      end

      def execute(target:, technique:, recipe:, exploit_name: nil, payload: nil, flag_regex: nil)
        r = @results.empty? ? {executed: true, success: true} : @results.shift
        r[:technique] = technique
        r
      end
    end
  end

  it "decides, executes the plan, records the outcome and stops on success" do
    executor = stub_executor.new([{executed: true, success: true}])
    result = described_class.run(
      target: "192.168.56.10", facts: facts_text, trail: trail,
      executor: executor, max_attempts: 3, seed: 42
    )
    expect(result[:status]).to eq("success")
    expect(result[:steps].size).to eq(1)
    expect(result[:steps].first[:technique]).to eq("ret2plt")
    expect(result[:steps].first[:executed]).to be(true)
    # The closed loop: the outcome is trailed
    events = File.readlines(trail_path).map { |l| JSON.parse(l) }
    expect(events.map { |e| e["type"] }).to include("outcome")
  end

  it "the flag the executor reports surfaces in the steps (the proof on screen)" do
    flag = "FLAG{augure_decides_lictor_executes}"
    executor = stub_executor.new([{executed: true, success: true, flag: flag}])
    result = described_class.run(
      target: "192.168.56.10", facts: facts_text, trail: trail,
      executor: executor, max_attempts: 3, seed: 42
    )
    expect(result[:steps].first[:flag]).to eq(flag),
      "the executor's flag never reached the steps - the run output cannot prove success"
  end

  it "adapts: a failed attempt feeds the priors and the next attempt avoids it" do
    # ret2plt fails twice (priors shift), then the executor "succeeds" on anything.
    results = [{executed: true, success: false}, {executed: true, success: false},
      {executed: true, success: true}]
    executor = stub_executor.new(results)
    result = described_class.run(
      target: "192.168.56.10", facts: facts_text, trail: trail,
      executor: executor, max_attempts: 5, seed: 42
    )
    expect(result[:status]).to eq("success")
    expect(result[:steps].size).to eq(3)
    expect(result[:steps].map { |s| s[:technique] }).to all(be_a(String))
  end

  it "respects the budget" do
    executor = stub_executor.new([{executed: true, success: false}, {executed: true, success: false},
      {executed: true, success: false}])
    result = described_class.run(
      target: "192.168.56.10", facts: facts_text, trail: trail,
      executor: executor, max_attempts: 2, seed: 42
    )
    expect(result[:status]).to eq("budget-exhausted")
    expect(result[:steps].size).to eq(2)
  end
end

RSpec.describe "the run's auto-scaffold" do
  let(:dir) { Dir.mktmpdir }
  let(:trail) { Lictor::Trail.new(File.join(dir, "t.jsonl")) }
  let(:repo) { File.join(dir, "ronin-repo", "exploits") }

  it "scaffolds the exploit when discovery comes up empty, then runs it" do
    builder = ["../../augure/profiler/spec/support/binary_builder.rb",
      "../augure/profiler/spec/support/binary_builder.rb"]
      .map { |p| File.expand_path(p, __dir__) }
      .find { |p| File.file?(p) }
    require_relative builder
    binary = ProfilerBinaryBuilder.vulnerable
    FileUtils.mkdir_p(repo)
    File.write(File.join(dir, "target.facts"),
      "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\n" \
      "win_symbol(\"win\", 4196182).\ngadget(\"ret_align\", 4196100).\n" \
      "target_function(\"true\").\n")

    executor = Class.new do
      def initialize(repo, technique)
        @repo = repo
        @technique = technique
      end

      def execute(target:, technique:, recipe:, exploit_name: nil, payload: nil, flag_regex: nil)
        if Dir.empty?(@repo)
          {executed: false, success: nil, note: "no #{@technique} exploit"}
        else
          @ran = Dir.children(@repo).first
          {executed: true, success: true, technique: technique, exploit: @ran}
        end
      end
    end.new(repo, "ret2func")

    result = Lictor::Run.run(target: "192.168.56.10",
      facts: File.read(File.join(dir, "target.facts")), trail: trail,
      executor: executor, max_attempts: 3,
      packs: Lictor::TechniquePacks.load(nil), binary: binary, repo_dir: repo)
    expect(result[:status]).to eq("success")
    expect(Dir.children(repo)).to include("lab_ret2func_001.rb")
    scaffolded = JSON.parse(File.readlines(File.join(dir, "t.jsonl")).map do |l|
      JSON.parse(l)
    end.find { |e| e["type"] == "scaffold" }.to_json)
    expect(scaffolded["offset_source"]).to eq("static-frame")
  end
end

RSpec.describe "the manual executor does not poison the priors" do
  let(:dir) { Dir.mktmpdir }
  let(:trail_path) { File.join(dir, "t.jsonl") }
  let(:trail) { Lictor::Trail.new(trail_path) }
  let(:facts_text) do
    "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\nplt(\"system\").\n" \
      "gadget(\"pop_rdi_ret\", 1).\nvuln_hint(\"unsafe_func:gets\").\n"
  end

  it "a handoff run records NO outcome event (nothing was attempted)" do
    executor = Class.new do
      def execute(**)
        {executed: false, success: nil, handoff: "print the recipe, execute nothing"}
      end
    end
    result = Lictor::Run.run(target: "192.168.56.10", facts: facts_text, trail: trail,
      executor: executor.new, max_attempts: 2, seed: 42)
    events = File.file?(trail_path) ? File.readlines(trail_path).map { |l| JSON.parse(l) } : []
    expect(events.map { |e| e["type"] }).not_to include("outcome")
    expect(result[:status]).to eq("handoff")
    expect(result[:steps].size).to eq(1) # one recipe, nothing changes between handoff attempts
  end

  it "the priors stay at the defaults after a handoff-only run" do
    executor = Class.new do
      def execute(**)
        {executed: false, success: nil, handoff: "handoff"}
      end
    end
    Lictor::Run.run(target: "192.168.56.10", facts: facts_text, trail: trail,
      executor: executor.new, max_attempts: 2, seed: 42)
    defaults = Lictor::Priors.from_trail(Lictor::Trail.new(File.join(dir, "empty.jsonl")))
    after = Lictor::Priors.from_trail(trail)
    expect(after["ret2plt"]).to eq(defaults["ret2plt"])
  end
end

RSpec.describe "the leak capture between attempts" do
  let(:dir) { Dir.mktmpdir }
  let(:trail_path) { File.join(dir, "t.jsonl") }
  let(:trail) { Lictor::Trail.new(trail_path) }
  let(:facts_text) do
    "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\nplt(\"system\").\n" \
      "gadget(\"pop_rdi_ret\", 1).\nvuln_hint(\"unsafe_func:gets\").\n"
  end

  it "the output's hex leaks become leaked_address facts for the next attempt" do
    executor_class = Class.new do
      def initialize(outputs)
        @outputs = outputs
      end

      def execute(**)
        {executed: true, success: false, output: @outputs.shift.to_s}
      end
    end
    result = Lictor::Run.run(target: "192.168.56.10:9999", facts: facts_text, trail: trail,
      executor: executor_class.new(["win() at 0xdeadbeef\n", "second"]), max_attempts: 2, seed: 42)
    expect(result[:leaks]).to eq({"win" => 0xdeadbeef})
    events = File.readlines(trail_path).map { |l| JSON.parse(l) }
    leaked = events.find { |e| e["type"] == "leak" }
    expect(leaked["addresses"]).to eq("win" => "0xdeadbeef")
  end

  it "no output, no leak event" do
    executor_class = Class.new do
      def execute(**)
        {executed: true, success: false}
      end
    end
    result = Lictor::Run.run(target: "192.168.56.10", facts: facts_text, trail: trail,
      executor: executor_class.new, max_attempts: 1, seed: 42)
    events = File.readlines(trail_path).map { |l| JSON.parse(l) }
    expect(events.map { |e| e["type"] }).not_to include("leak")
    expect(result[:leaks]).to eq({})
  end
end

RSpec.describe "the run manifest + resume" do
  let(:dir) { Dir.mktmpdir }
  let(:trail_path) { File.join(dir, "t.jsonl") }
  let(:trail) { Lictor::Trail.new(trail_path) }
  let(:manifest_path) { File.join(dir, "run.json") }
  let(:facts_text) do
    "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\nplt(\"system\").\n" \
      "gadget(\"pop_rdi_ret\", 1).\nvuln_hint(\"unsafe_func:gets\").\n"
  end
  let(:executor_class) do
    Class.new do
      def initialize(results)
        @results = results
      end

      def execute(**)
        @results.empty? ? {executed: true, success: false} : @results.shift
      end
    end
  end

  it "one stable run id carries every event of the loop" do
    result = Lictor::Run.run(target: "192.168.56.10", facts: facts_text, trail: trail,
      executor: executor_class.new([{executed: true, success: true}]), max_attempts: 2,
      seed: 42, manifest_path: manifest_path)
    expect(result[:run_id]).to be_a(String)
    events = File.readlines(trail_path).map { |l| JSON.parse(l) }
    ids = events.select { |e| e["type"] == "outcome" }.map { |e| e["run"] }
    expect(ids).to all(eq(result[:run_id]))
  end

  it "the manifest is written per attempt and resume continues the same run" do
    # attempt 1 fails, the process "dies" (max_attempts 1), the manifest
    # carries the state; resume continues with the SAME id
    first = Lictor::Run.run(target: "192.168.56.10", facts: facts_text, trail: trail,
      executor: executor_class.new([{executed: true, success: false}]), max_attempts: 1,
      seed: 42, manifest_path: manifest_path)
    expect(first[:status]).to eq("budget-exhausted")
    manifest = JSON.parse(File.read(manifest_path))
    expect(manifest["id"]).to eq(first[:run_id])
    expect(manifest["attempts"].size).to eq(1)

    second = Lictor::Run.run(target: "192.168.56.10", facts: facts_text, trail: trail,
      executor: executor_class.new([{executed: true, success: true}]), max_attempts: 2,
      seed: 42, manifest_path: manifest_path, resume: first[:run_id])
    expect(second[:run_id]).to eq(first[:run_id])
    expect(second[:status]).to eq("success")
    expect(second[:steps].size).to eq(1) # only the NEW attempt
    events = File.readlines(trail_path).map { |l| JSON.parse(l) }
    ids = events.select { |e| e["type"] == "outcome" }.map { |e| e["run"] }
    expect(ids).to all(eq(first[:run_id]))
  end

  it "resume with a mismatched id is refused loudly" do
    Lictor::Run.run(target: "192.168.56.10", facts: facts_text, trail: trail,
      executor: executor_class.new([]), max_attempts: 1, seed: 42, manifest_path: manifest_path)
    expect do
      Lictor::Run.run(target: "192.168.56.10", facts: facts_text, trail: trail,
        executor: executor_class.new([]), max_attempts: 1, seed: 42,
        manifest_path: manifest_path, resume: "not-the-id")
    end.to raise_error(Lictor::RunError, /manifest holds run/)
  end
end

RSpec.describe "the static read is trailed (the measure -> decision chain)" do
  let(:dir) { Dir.mktmpdir }
  let(:trail_path) { File.join(dir, "t.jsonl") }
  let(:trail) { Lictor::Trail.new(trail_path) }
  let(:facts_text) do
    # NO vuln_hint: only the static read can supply it - the decision
    # proves the read happened, the trail proves it was ATTEMPTED
    "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\n" \
      "win_symbol(\"win\", 4196182).\ngadget(\"ret_align\", 4196100).\n" \
      "target_function(\"true\").\n"
  end

  it "the enrichment leaves a measure event even when the decision follows" do
    builder = ["../../augure/profiler/spec/support/binary_builder.rb",
      "../augure/profiler/spec/support/binary_builder.rb"]
      .map { |p| File.expand_path(p, __dir__) }
      .find { |p| File.file?(p) }
    require_relative builder
    executor_class = Class.new do
      def execute(**)
        {executed: false, success: nil}
      end
    end
    Lictor::Run.run(target: "192.168.56.10", facts: facts_text, trail: trail,
      executor: executor_class.new, max_attempts: 1, seed: 42,
      binary: ProfilerBinaryBuilder.vulnerable)
    events = File.readlines(trail_path).map { |l| JSON.parse(l) }
    measure = events.find { |e| e["type"] == "measure" }
    expect(measure).not_to be_nil, "the static read left no trail event - " \
      "a swallowed error class (NameError under the bare rescue) hides here"
    expect(measure["sink"]).to eq("strcpy")
    expect(measure["source"]).to eq("static-frame")
  end
end
