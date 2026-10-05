# frozen_string_literal: true

require "lictor"
require "open3"
require "tmpdir"

RSpec.describe Lictor::Profiler do
  let(:dir) { Dir.mktmpdir }
  let(:stub_cmd) do
    path = File.join(dir, "fake-augure-profile")
    File.write(path, <<~SH)
      #!/bin/sh
      echo 'nx("true").'
      echo 'pie("false").'
    SH
    File.chmod(0o755, path)
    path
  end

  it "profiles an ELF binary through the augure-profile subprocess" do
    binary = File.join(dir, "app.elf")
    File.write(binary, "\x7fELF-binaries")
    facts = described_class.run(binary, cmd: stub_cmd)
    expect(facts).to include('nx("true").')
  end

  it "points at the gem when augure-profile is missing" do
    expect {
      described_class.run(File.join(dir, "missing.elf"), cmd: File.join(dir, "nope"))
    }.to raise_error(Lictor::ProfilerError, /gem install augure-profiler/)
  end
end

RSpec.describe "bin/lictor plan with a binary" do
  let(:exe) { File.expand_path("../bin/lictor", __dir__) }
  let(:dir) { Dir.mktmpdir }
  let(:stub_cmd) do
    path = File.join(dir, "fake-augure-profile")
    File.write(path, <<~SH)
      #!/bin/sh
      cat #{File.expand_path("fixtures/profiler_facts.facts", __dir__)}
    SH
    File.chmod(0o755, path)
    path
  end
  it "profiles the binary, decides and trails both steps" do
    binary = File.join(dir, "target.elf")
    File.write(binary, "\x7fELF-target")
    trail = File.join(dir, "trail.jsonl")
    out, _err, status = Open3.capture3(exe, "plan", binary,
      "--profile-cmd", stub_cmd, "-t", trail)
    expect(status.exitstatus).to eq(0)
    expect(out).to include("selected:   ret2plt")

    runs = Lictor::Trail.new(trail).runs
    expect(runs.last[:profiled]).to eq(binary)
  end

  it "still accepts a hand-written facts file unchanged" do
    path = File.join(dir, "target.facts")
    File.write(path, File.read(File.expand_path("fixtures/profiler_facts.facts", __dir__)))
    out, _err, status = Open3.capture3(exe, "plan", path,
      "-t", File.join(dir, "trail.jsonl"))
    expect(status.exitstatus).to eq(0)
    expect(out).to include("selected:   ret2plt")
  end
end
