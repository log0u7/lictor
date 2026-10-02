# frozen_string_literal: true

require "lictor"
require "tmpdir"

RSpec.describe Lictor::Gates do
  let(:allowlist_path) do
    path = File.join(Dir.mktmpdir, "targets.yml")
    File.write(path, "192.168.56.10\n192.168.56.11:4444\n")
    path
  end

  describe ".allowlist" do
    it "reads explicit host and host:port entries" do
      expect(described_class.allowlist(allowlist_path))
        .to contain_exactly("192.168.56.10", "192.168.56.11:4444")
    end

    it "rejects comments, blanks and wildcards" do
      bad = File.join(File.dirname(allowlist_path), "bad.yml")
      File.write(bad, "# comment\n\n*.lab.local\n10.0.0.*\n")
      expect { described_class.allowlist(bad) }
        .to raise_error(Lictor::Unauthorized, /wildcards are not allowed/)
    end
  end

  describe ".require_authorized!" do
    it "raises without the explicit consent flag" do
      expect { described_class.require_authorized!(false, allowlist_path) }
        .to raise_error(Lictor::Unauthorized, /--i-am-authorized/)
    end

    it "raises when the target is not on the allowlist" do
      expect { described_class.require_authorized!(true, allowlist_path, target: "10.9.9.9") }
        .to raise_error(Lictor::Unauthorized, /10\.9\.9\.9 is not in the allowlist/)
    end

    it "requires an explicit target for an authorized run" do
      expect { described_class.require_authorized!(true, allowlist_path) }
        .to raise_error(Lictor::Unauthorized, /explicit --target/)
    end

    it "passes for an allowlisted target" do
      expect(described_class.require_authorized!(true, allowlist_path, target: "192.168.56.10")).to eq(true)
    end
  end
end

RSpec.describe Lictor::Handoff do
  let(:facts) { "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\nplt(\"system\").\ngadget(\"pop_rdi_ret\", 1).\nvuln_hint(\"unsafe_func:gets\").\n" }

  it "produces an msfconsole recipe for the decided technique" do
    recipe = described_class.recipe("ret2plt")
    expect(recipe[:module]).to eq("exploit/multi/handler")
    expect(recipe[:console]).to include("msfconsole")
    expect(recipe[:console]).to include("ret2plt")
  end

  it "returns a manual handoff for techniques without a module mapping" do
    recipe = described_class.recipe("heap_tcache")
    expect(recipe[:module]).to eq("manual")
  end

  it "hands off the full decision with recipes and provenance" do
    result = described_class.plan(facts: facts, seed: 42)
    expect(result[:selected]).to eq("ret2plt")
    expect(result[:recipe]).not_to be_nil
    expect(result[:explain]).to include(:provenance)
  end
end

RSpec.describe Lictor::Trail do
  it "appends one JSON line per event and reads them back" do
    path = File.join(Dir.mktmpdir, "trail.jsonl")
    trail = described_class.new(path)
    trail.record(run: "r1", decision: "ret2plt", mode: "handoff")
    trail.record(run: "r1", event: "recipe_printed")
    lines = File.readlines(path).map { |l| JSON.parse(l) }
    expect(lines.size).to eq(2)
    expect(lines[0]["decision"]).to eq("ret2plt")
    expect(lines[0]).to have_key("timestamp")
  end
end
