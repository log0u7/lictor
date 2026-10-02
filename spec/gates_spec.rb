# frozen_string_literal: true

require "lictor"
require "tmpdir"

RSpec.describe Lictor::Gates do
  let(:dir) { Dir.mktmpdir }
  let(:allowlist_path) do
    path = File.join(dir, "targets.yml")
    File.write(path, "192.168.56.10\n192.168.56.11:4444\n")
    path
  end

  describe ".allowlist" do
    it "reads explicit host and host:port entries" do
      expect(described_class.allowlist(allowlist_path))
        .to contain_exactly("192.168.56.10", "192.168.56.11:4444")
    end

    it "rejects comments, blanks and wildcards" do
      bad = File.join(dir, "bad.yml")
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

    it "a host:port entry authorizes the host (colon-delimited, no .1/.10 confusion)" do
      expect(described_class.require_in_scope!(allowlist_path, "192.168.56.11")).to eq(true)
      expect { described_class.require_in_scope!(allowlist_path, "192.168.56.1") }
        .to raise_error(Lictor::Unauthorized)
    end

    it "requires the allowlist file" do
      expect { described_class.require_in_scope!(nil, "192.168.56.10") }
        .to raise_error(Lictor::Unauthorized, /allowlist file is required/)
    end
  end

  it "has no consent flag: the allowlist artifact and the trail are the controls" do
    expect(described_class).not_to respond_to(:require_authorized!)
  end
end
