# frozen_string_literal: true

require "lictor"
require "tmpdir"

RSpec.describe "bin/lictor init" do
  let(:exe) { File.expand_path("../bin/lictor", __dir__) }

  it "scaffolds the engagement setup and prints the next commands" do
    dir = Dir.mktmpdir
    out, _err, status = Open3.capture3(exe, "init", chdir: dir)
    expect(status.exitstatus).to eq(0)
    expect(File.read(File.join(dir, "targets.yml"))).to include("192.168.56.10")
    expect(File.file?(File.join(dir, "examples/ret2win.facts"))).to be(true)
    expect(out).to include("lictor doctor")
    expect(out).to include("lictor plan examples/ret2win.facts")
  end

  it "refuses to overwrite an existing setup" do
    dir = Dir.mktmpdir
    File.write(File.join(dir, "lictor.yml"), "trail: mine.jsonl\n")
    _out, err, status = Open3.capture3(exe, "init", chdir: dir)
    expect(status.exitstatus).not_to eq(0)
    expect(err).to include("already exists")
  end
end

RSpec.describe "bin/lictor doctor" do
  let(:exe) { File.expand_path("../bin/lictor", __dir__) }

  def scaffold(dir, allowlist: "192.168.56.10\n")
    File.write(File.join(dir, "lictor.yml"), "trail: t.jsonl\n")
    File.write(File.join(dir, "targets.yml"), allowlist)
  end

  it "reports ok on a clean setup" do
    dir = Dir.mktmpdir
    scaffold(dir)
    out, _err, status = Open3.capture3(exe, "doctor", chdir: dir)
    expect(status.exitstatus).to eq(0)
    expect(out).to include("ok")
    expect(out).not_to include("FAIL")
  end

  it "fails when lictor.yml is missing and says how to fix it" do
    dir = Dir.mktmpdir
    _out, err, status = Open3.capture3(exe, "doctor", chdir: dir)
    expect(status.exitstatus).not_to eq(0)
    expect(err + "").to include("lictor init")
  end
end
