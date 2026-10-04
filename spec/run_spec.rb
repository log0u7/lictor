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

      def execute(target:, technique:, recipe:, exploit_name: nil, payload: nil)
        r = @results.empty? ? {executed: true, success: true} : @results.shift
        r[:technique] = technique
        r
      end
    end
  end

  let(:token) { Lictor::Consent.issue(trail, "192.168.56.10", confirm_input: "192.168.56.10\n") }

  it "decides, executes the plan, records the outcome and stops on success" do
    executor = stub_executor.new([{executed: true, success: true}])
    result = described_class.run(
      target: "192.168.56.10", facts: facts_text, trail: trail,
      executor: executor, consent_token: token, max_attempts: 3, seed: 42
    )
    expect(result[:status]).to eq("success")
    expect(result[:steps].size).to eq(1)
    expect(result[:steps].first[:technique]).to eq("ret2plt")
    expect(result[:steps].first[:executed]).to be(true)
    # The closed loop: the outcome is trailed
    events = File.readlines(trail_path).map { |l| JSON.parse(l) }
    expect(events.map { |e| e["type"] }).to include("outcome")
  end

  it "adapts: a failed attempt feeds the priors and the next attempt avoids it" do
    # ret2plt fails twice (priors shift), then the executor "succeeds" on anything.
    results = [{executed: true, success: false}, {executed: true, success: false}, {executed: true, success: true}]
    executor = stub_executor.new(results)
    result = described_class.run(
      target: "192.168.56.10", facts: facts_text, trail: trail,
      executor: executor, consent_token: token, max_attempts: 5, seed: 42
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
      executor: executor, consent_token: token, max_attempts: 2, seed: 42
    )
    expect(result[:status]).to eq("budget-exhausted")
    expect(result[:steps].size).to eq(2)
  end

  it "requires a valid consent token for the exact target" do
    expect {
      described_class.run(target: "192.168.56.10", facts: facts_text, trail: trail,
        executor: stub_executor.new([]), consent_token: nil, max_attempts: 1)
    }.to raise_error(Lictor::Unauthorized, /consent/)
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

    token = Lictor::Consent.issue(trail, "192.168.56.10", confirm_input: "192.168.56.10\n")
    executor = Class.new do
      def initialize(repo, technique)
        @repo = repo
        @technique = technique
      end

      def execute(target:, technique:, recipe:, exploit_name: nil, payload: nil)
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
      executor: executor, consent_token: token, max_attempts: 3,
      packs: Lictor::TechniquePacks.load(nil), binary: binary, repo_dir: repo)
    expect(result[:status]).to eq("success")
    expect(Dir.children(repo)).to include("lab_ret2func_001.rb")
    scaffolded = JSON.parse(File.readlines(File.join(dir, "t.jsonl")).map { |l| JSON.parse(l) }.find { |e| e["type"] == "scaffold" }.to_json)
    expect(scaffolded["offset_source"]).to eq("static-frame")
  end
end
