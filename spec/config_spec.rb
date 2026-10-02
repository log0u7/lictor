# frozen_string_literal: true

require "lictor"
require "tmpdir"

RSpec.describe Lictor::Config do
  let(:dir) { Dir.mktmpdir }

  it "returns empty settings when no config file exists" do
    expect(described_class.load(File.join(dir, "none.yml"))).to eq({})
  end

  it "reads allowlist, trail, nmap and profile_cmd" do
    path = File.join(dir, "lictor.yml")
    File.write(path, <<~YML)
      allowlist: targets.yml
      trail: runs.jsonl
      nmap: /usr/bin/nmap
      profile_cmd: augure-profile
      seed: 42
    YML
    expect(described_class.load(path)).to eq(
      allowlist: "targets.yml", trail: "runs.jsonl",
      nmap: "/usr/bin/nmap", profile_cmd: "augure-profile", seed: 42
    )
  end

  it "defaults to lictor.yml in the current directory" do
    Dir.chdir(dir) do
      expect(described_class.load).to eq({})
    end
  end
end

RSpec.describe "bin/lictor reads lictor.yml" do
  let(:exe) { File.expand_path("../bin/lictor", __dir__) }

  it "plan works with no -a flag when the config names the allowlist" do
    dir = Dir.mktmpdir
    File.write(File.join(dir, "targets.yml"), "192.168.56.10\n")
    File.write(File.join(dir, "lictor.yml"), "allowlist: targets.yml\ntrail: t.jsonl\n")
    File.write(File.join(dir, "target.facts"),
      "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\n" \
      "plt(\"system\").\ngadget(\"pop_rdi_ret\", 1).\nvuln_hint(\"unsafe_func:gets\").\n")
    out, _err, status = Open3.capture3(exe, "plan", "target.facts", chdir: dir)
    expect(status.exitstatus).to eq(0)
    expect(out).to include("selected:   ret2plt")
    expect(File.exist?(File.join(dir, "t.jsonl"))).to be(true)
  end

  it "flags override the config" do
    dir = Dir.mktmpdir
    File.write(File.join(dir, "targets.yml"), "192.168.56.10\n")
    File.write(File.join(dir, "other.yml"), "10.9.9.9\n")
    File.write(File.join(dir, "lictor.yml"), "allowlist: targets.yml\n")
    File.write(File.join(dir, "target.facts"),
      "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\n" \
      "plt(\"system\").\ngadget(\"pop_rdi_ret\", 1).\nvuln_hint(\"unsafe_func:gets\").\n")
    out, _, status = Open3.capture3(exe, "plan", "target.facts", "-a", "other.yml", chdir: dir)
    expect(status.exitstatus).to eq(0)
    expect(out).to include("selected:   ret2plt")
  end
end
