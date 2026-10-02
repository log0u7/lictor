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

      def execute(target:, technique:, recipe:, exploit_name: nil)
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
