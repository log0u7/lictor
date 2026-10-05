# frozen_string_literal: true

require "lictor"
require "json"
require "tmpdir"

RSpec.describe Lictor::Priors do
  let(:trail_path) { File.join(Dir.mktmpdir, "trail.jsonl") }
  let(:trail) { Lictor::Trail.new(trail_path) }

  it "starts from the augure defaults when the trail is empty" do
    priors = described_class.from_trail(trail)
    expect(priors["ret2plt"]).to eq(Augure::Pipeline.default_priors["ret2plt"])
  end

  it "feeds outcomes back into the bandit priors (the closed loop)" do
    trail.record(run: "r1", type: "outcome", technique: "ret2plt", success: true)
    trail.record(run: "r1", type: "outcome", technique: "ret2plt", success: true)
    trail.record(run: "r2", type: "outcome", technique: "ret2plt", success: false)

    base = Augure::Pipeline.default_priors["ret2plt"]
    priors = described_class.from_trail(trail)
    expect(priors["ret2plt"]).to eq([base[0] + 2, base[1] + 1])
  end

  it "ignores non-outcome events" do
    trail.record(run: "r1", mode: "handoff", selected: "rop")
    priors = described_class.from_trail(trail)
    expect(priors["rop"]).to eq(Augure::Pipeline.default_priors["rop"])
  end

  it "adapts the next decision through the bandit (end to end)" do
    facts = "vuln(\"fmtstr\").\nfmtstr_read(\"true\").\ngot_overwrite_target(\"true\").\n" \
            "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\nrelro(\"partial\").\n"
    base = Augure::Pipeline.analyze(facts: facts, seed: 42)
    expect(base[:ranking].first).to eq("fmtstr_leak")

    # Three recorded successes on got_overwrite flip the ranking.
    3.times { trail.record(run: "r", type: "outcome", technique: "got_overwrite", success: true) }
    adapted = Augure::Pipeline.analyze(
      facts: facts,
      priors: described_class.from_trail(trail),
      seed: 42
    )
    expect(adapted[:ranking].first).to eq("got_overwrite")
  end
end

RSpec.describe Lictor::Trail do
  it "is private from birth: the audit record is created 0600" do
    dir = Dir.mktmpdir
    path = File.join(dir, "t.jsonl")
    trail = described_class.new(path)
    trail.record(run: "r1", type: "outcome")
    expect(File.stat(path).mode.to_s(8)).to match(/600$/)
  end
  let(:trail_path) { File.join(Dir.mktmpdir, "trail.jsonl") }
  let(:trail) { described_class.new(trail_path) }

  describe "#runs" do
    it "aggregates plan and outcome events per run" do
      trail.record(run: "r1", type: "plan", mode: "handoff", selected: "ret2plt",
        applicable: %w[ret2plt rop], explain: {provenance: {"ret2plt" => []}})
      trail.record(run: "r1", type: "outcome", technique: "ret2plt", success: true)
      trail.record(run: "r2", type: "plan", mode: "handoff", selected: "rop",
        applicable: ["rop"], explain: {provenance: {}})

      runs = trail.runs
      expect(runs.size).to eq(2)
      expect(runs.first[:run]).to eq("r1")
      expect(runs.first[:selected]).to eq("ret2plt")
      expect(runs.first[:outcomes]).to eq([{technique: "ret2plt", success: true, executed: false}])
      expect(runs.last[:outcomes]).to be_empty
    end

    it "returns [] on a fresh trail" do
      expect(described_class.new(File.join(Dir.mktmpdir, "none.jsonl")).runs).to eq([])
    end
  end
end

RSpec.describe Lictor::Report do
  let(:trail_path) { File.join(Dir.mktmpdir, "trail.jsonl") }
  let(:trail) { Lictor::Trail.new(trail_path) }

  before do
    trail.record(run: "r1", type: "plan", mode: "handoff", selected: "ret2plt",
      applicable: %w[ret2plt rop], facts_file: "target.facts",
      explain: {provenance: {"ret2plt" => [
        {rule: :app_ret2plt, evidence: [["vuln", "sof"], ["plt", "system"]]}
      ]}})
    trail.record(run: "r1", type: "outcome", technique: "ret2plt", success: true)
  end

  it "renders an auditable markdown engagement report" do
    md = described_class.from_trail(trail)
    expect(md).to include("# Engagement report")
    expect(md).to include("## Run `r1`")
    expect(md).to include("selected: **ret2plt**")
    expect(md).to include("app_ret2plt")
    expect(md).to include("vuln=sof")
    expect(md).to include("outcome: **success** (ret2plt)")
  end

  it "claims predictions, not field results" do
    expect(described_class.from_trail(trail)).to include("model predictions")
  end

  it "writes to disk via .to_file" do
    out = File.join(Dir.mktmpdir, "report.md")
    described_class.to_file(out, trail)
    expect(File.read(out)).to include("# Engagement report")
  end
end
