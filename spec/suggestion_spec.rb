# frozen_string_literal: true

require "lictor"
require "json"
require "tmpdir"

RSpec.describe Lictor::Suggestion do
  let(:dir) { Dir.mktmpdir }
  let(:trail) { Lictor::Trail.new(File.join(dir, "t.jsonl")) }
  let(:base) do
    "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\nrelro(\"partial\").\n"
  end

  it "merges suggested facts and reports the decision delta" do
    result = described_class.apply(base_facts: base,
      suggested: "plt(\"system\").\ngadget(\"pop_rdi_ret\", 1).\nvuln_hint(\"unsafe_func:gets\").\n",
      trail: trail, target: "192.168.56.10", seed: 42)

    expect(result[:applicable_before]).not_to include("ret2plt")
    expect(result[:applicable_after]).to include("ret2plt")
    expect(result[:added]).to contain_exactly(
      ["plt", ["system"]], ["gadget", ["pop_rdi_ret", 1]], ["vuln_hint", ["unsafe_func:gets"]]
    )
    expect(result[:facts]["plt"]).to include(["system"])
  end

  it "rejects facts outside the schema - an agent cannot assert applicability" do
    expect {
      described_class.apply(base_facts: base, suggested: "applicable(ret2plt).\n",
        trail: trail, target: "192.168.56.10")
    }.to raise_error(Augure::UnknownPredicate, /applicable/)
  end

  it "records the suggestion in the trail: who proposed what, what changed" do
    described_class.apply(base_facts: base,
      suggested: "plt(\"system\").\n", trail: trail, target: "192.168.56.10", seed: 42)
    event = JSON.parse(File.readlines(File.join(dir, "t.jsonl")).last)
    expect(event["type"]).to eq("suggest")
    expect(event["target"]).to eq("192.168.56.10")
    expect(event["added"]).to eq([["plt", ["system"]]])
    expect(event).to have_key("applicable_before")
    expect(event).to have_key("applicable_after")
  end

  it "reports an empty delta when suggestions change nothing" do
    result = described_class.apply(base_facts: base, suggested: "nx(\"true\").\n",
      trail: trail, target: "192.168.56.10", seed: 42)
    expect(result[:added]).to be_empty
    expect(result[:applicable_after]).to eq(result[:applicable_before])
  end
end
