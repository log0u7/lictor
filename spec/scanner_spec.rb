# frozen_string_literal: true

require "lictor"
require "tmpdir"

RSpec.describe Lictor::Scanner do
  let(:dir) { Dir.mktmpdir }
  let(:stub_nmap) do
    path = File.join(dir, "fake-nmap")
    # The subprocess contract: nmap -sV -Pn -oX <out> <target>
    File.write(path, <<~SH)
      #!/bin/sh
      out=""
      prev=""
      for arg in "$@"; do
        if [ "$prev" = "-oX" ]; then out="$arg"; fi
        prev="$arg"
      done
      cp #{File.expand_path("fixtures/nmap_scan.xml", __dir__)} "$out"
    SH
    File.chmod(0o755, path)
    path
  end

  it "runs nmap and returns the parsed target inventory" do
    out = File.join(dir, "scan.xml")
    targets = described_class.run("192.168.56.10", out: out, nmap_cmd: stub_nmap)
    expect(File.exist?(out)).to be(true)
    expect(targets.map { |t| t[:host] }).to include("192.168.56.10")
    expect(targets.map { |t| t[:port] }).to include(22, 80)
  end

  it "fails loudly when nmap is not installed" do
    expect {
      described_class.run("192.168.56.10", out: File.join(dir, "x.xml"),
        nmap_cmd: File.join(dir, "no-such-nmap"))
    }.to raise_error(Lictor::ScanError, /nmap/)
  end
end

RSpec.describe "bin/lictor scan" do
  let(:exe) { File.expand_path("../bin/lictor", __dir__) }
  let(:dir) { Dir.mktmpdir }
  let(:stub_nmap) do
    path = File.join(dir, "fake-nmap")
    File.write(path, <<~SH)
      #!/bin/sh
      out=""
      prev=""
      for arg in "$@"; do
        if [ "$prev" = "-oX" ]; then out="$arg"; fi
        prev="$arg"
      done
      cp #{File.expand_path("fixtures/nmap_scan.xml", __dir__)} "$out"
    SH
    File.chmod(0o755, path)
    path
  end
  let(:allowlist) do
    p = File.join(dir, "targets.yml")
    File.write(p, "192.168.56.10:22\n")
    p
  end

  it "scans a host, trails and prints the inventory" do
    trail = File.join(dir, "trail.jsonl")
    out, _err, status = Open3.capture3(exe, "scan", "192.168.56.10",
      "--nmap", stub_nmap, "-t", trail)
    expect(status.exitstatus).to eq(0)
    expect(out).to include("192.168.56.10:22")

    runs = Lictor::Trail.new(trail).runs
    expect(runs.last[:scanned]).to eq("192.168.56.10")
  end

  it "shows the scan in the report" do
    trail = File.join(dir, "trail.jsonl")
    Open3.capture3(exe, "scan", "192.168.56.10",
      "--nmap", stub_nmap, "-t", trail)
    report = Lictor::Report.from_trail(Lictor::Trail.new(trail))
    expect(report).to include("- scan: 192.168.56.10")
  end
end
