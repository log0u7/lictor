# frozen_string_literal: true

require "open3"
require "json"
require "tmpdir"

RSpec.describe "bin/lictor" do
  let(:exe) { File.expand_path("../bin/lictor", __dir__) }
  let(:facts_text) do
    "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\nplt(\"system\").\n" \
      "gadget(\"pop_rdi_ret\", 1).\nvuln_hint(\"unsafe_func:gets\").\n"
  end

  it "refuses to run without an allowlist" do
    path = File.join(Dir.mktmpdir, "target.facts")
    File.write(path, facts_text)
    _out, err, status = Open3.capture3(exe, "plan", path)
    expect(status.exitstatus).not_to eq(0)
    expect(err).to include("UNAUTHORIZED")
  end

  it "refuses a wildcard allowlist" do
    dir = Dir.mktmpdir
    path = File.join(dir, "target.facts")
    File.write(path, facts_text)
    list = File.join(dir, "targets.yml")
    File.write(list, "*.lab.local\n")
    _out, err, status = Open3.capture3(exe, "plan", path, "-a", list)
    expect(status.exitstatus).not_to eq(0)
    expect(err).to include("wildcards")
  end

  it "emits allowlist candidates from an nmap XML scan (no gates: candidates only)" do
    xml = File.expand_path("fixtures/nmap_scan.xml", __dir__)
    out, _err, status = Open3.capture3(exe, "recon", xml)
    expect(status.exitstatus).to eq(0)
    expect(out).to include("192.168.56.10:22")
    expect(out).to include("192.168.56.11:21")
    expect(out).not_to include("192.168.56.10:4444") # closed port
  end

  it "hands off the decision with a recipe and trails it (no consent flag needed)" do
    dir = Dir.mktmpdir
    path = File.join(dir, "target.facts")
    File.write(path, facts_text)
    list = File.join(dir, "targets.yml")
    File.write(list, "192.168.56.10\n")
    out, _err, status = Open3.capture3(exe, "plan", path, "-a", list,
                                       "-t", File.join(dir, "trail.jsonl"))
    expect(status.exitstatus).to eq(0)
    expect(out).to include("handoff")
    expect(out).to include("selected:   ret2plt")
    expect(out).to include("ronin-exploits")
    expect(JSON.parse(File.read(File.join(dir, "trail.jsonl")))).to have_key("selected")
  end

  it "has no consent flag anywhere" do
    out, _err, _status = Open3.capture3(exe, "--help")
    expect(out).not_to include("i-am-authorized")
  end
end
