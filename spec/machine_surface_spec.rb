# frozen_string_literal: true

require "open3"
require "json"
require "tmpdir"

RSpec.describe "bin/lictor machine surface" do
  let(:exe) { File.expand_path("../bin/lictor", __dir__) }

  it "plan --json emits a machine payload" do
    dir = Dir.mktmpdir
    Open3.capture3(exe, "init", chdir: dir) # the real user path scaffolds the example
    out, _err, status = Open3.capture3(exe, "plan", "examples/ret2win.facts", "--json", chdir: dir)
    expect(status.exitstatus).to eq(0)
    payload = JSON.parse(out)
    expect(payload).to include("applicable", "ranking", "selected", "explain")
    expect(payload.dig("explain", "provenance", "ret2func")).not_to be_empty
  end

  it "report --json emits runs as structured data" do
    dir = Dir.mktmpdir
    Open3.capture3(exe, "init", chdir: dir)
    trail = File.join(dir, "t.jsonl")
    Open3.capture3(exe, "plan", "examples/ret2win.facts", "-t", trail, chdir: dir)
    out, _err, status = Open3.capture3(exe, "report", "--json", "-t", trail, chdir: dir)
    expect(status.exitstatus).to eq(0)
    payload = JSON.parse(out)
    expect(payload["runs"].first["selected"]).to eq("ret2func")
  end

  it "help <command> documents a single command" do
    out, _err, status = Open3.capture3(exe, "help", "plan")
    expect(status.exitstatus).to eq(0)
    expect(out).to include("plan")
    expect(out).not_to include("recon <nmap.xml>")
  end
end
