# frozen_string_literal: true

require "lictor"
require "tmpdir"

RSpec.describe Lictor::Recon do
  let(:fixture) { File.expand_path("fixtures/nmap_scan.xml", __dir__) }

  describe ".from_nmap_xml" do
    it "inventories open services of live hosts only" do
      targets = described_class.from_nmap_xml(fixture)
      expect(targets).to eq([
        {host: "192.168.56.10", port: 22, service: "ssh", product: "OpenSSH", version: "8.9p1"},
        {host: "192.168.56.10", port: 80, service: "http", product: "nginx", version: "1.18.0"},
        {host: "192.168.56.11", port: 21, service: "ftp", product: "vsftpd", version: "2.3.4"}
      ])
    end
  end

  describe ".allowlist_candidates" do
    it "emits host:port entries matching the allowlist format" do
      expect(described_class.allowlist_candidates(fixture))
        .to contain_exactly("192.168.56.10:22", "192.168.56.10:80", "192.168.56.11:21")
    end

    it "never contains wildcards (the gate contract)" do
      described_class.allowlist_candidates(fixture).each do |entry|
        expect(entry).not_to include("*")
      end
    end
  end
end
