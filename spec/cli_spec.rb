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

  it "refuses targets outside the allowlist" do
    dir = Dir.mktmpdir
    path = File.join(dir, "target.facts")
    File.write(path, facts_text)
    list = File.join(dir, "targets.yml")
    File.write(list, "192.168.56.10\n")
    _out, err, status = Open3.capture3(exe, "plan", path, "-a", list, "--target", "10.9.9.9", "--i-am-authorized")
    expect(status.exitstatus).not_to eq(0)
    expect(err).to include("not in the allowlist")
  end

  it "hands off the decision with a recipe and trails it" do
    dir = Dir.mktmpdir
    path = File.join(dir, "target.facts")
    File.write(path, facts_text)
    list = File.join(dir, "targets.yml")
    File.write(list, "192.168.56.10\n")
    out, _err, status = Open3.capture3(exe, "plan", path, "-a", list, "--target", "192.168.56.10",
      "--i-am-authorized", "-t", File.join(dir, "trail.jsonl"))
    expect(status.exitstatus).to eq(0)
    expect(out).to include("handoff")
    expect(out).to include("selected:   ret2plt")
    expect(out).to include("msfconsole")
    expect(JSON.parse(File.read(File.join(dir, "trail.jsonl")))).to have_key("selected")
  end
end
