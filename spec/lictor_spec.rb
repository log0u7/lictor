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

  describe ".require_in_scope!" do
    it "raises when the target is not on the allowlist" do
      expect { described_class.require_in_scope!(allowlist_path, "10.9.9.9") }
        .to raise_error(Lictor::Unauthorized, /10\.9\.9\.9 is not in the allowlist/)
    end

    it "passes for an exact entry" do
      expect(described_class.require_in_scope!(allowlist_path, "192.168.56.10")).to eq(true)
    end

    it "a host:port entry authorizes the host (colon-delimited)" do
      expect(described_class.require_in_scope!(allowlist_path, "192.168.56.11")).to eq(true)
      expect { described_class.require_in_scope!(allowlist_path, "192.168.56.1") }
        .to raise_error(Lictor::Unauthorized)
    end
  end

  it "has no consent flag: the allowlist artifact and the trail are the controls" do
    expect(described_class).not_to respond_to(:require_authorized!)
  end
end

RSpec.describe Lictor::Handoff do
  let(:facts) { "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\nplt(\"system\").\ngadget(\"pop_rdi_ret\", 1).\nvuln_hint(\"unsafe_func:gets\").\n" }

  it "produces a ronin recipe for the decided technique" do
    recipe = described_class.recipe("ret2plt")
    expect(recipe[:runner]).to eq("ronin")
    expect(recipe[:mixin]).to eq("Binary")
    expect(recipe[:console]).to include("ronin-exploits run")
    expect(recipe[:console]).to include("--technique ret2plt")
  end

  it "maps format-string techniques to the FormatString mixin" do
    expect(described_class.recipe("fmtstr_leak")[:mixin]).to eq("FormatString")
  end

  it "defers the exploit name to the operator's repos" do
    recipe = described_class.recipe("ret2plt")
    expect(recipe[:console]).to include("<exploit-name-from-your-repos>")
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
