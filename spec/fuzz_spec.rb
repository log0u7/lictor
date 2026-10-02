# frozen_string_literal: true

require "open3"
require "json"
require "tmpdir"

builder = ["../../augure/profiler/spec/support/binary_builder.rb",
           "../augure/profiler/spec/support/binary_builder.rb"]
  .map { |p| File.expand_path(p, __dir__) }
  .find { |p| File.file?(p) }
require_relative builder

RSpec.describe "bin/lictor fuzz" do
  let(:exe) { File.expand_path("../bin/lictor", __dir__) }
  let(:dir) { Dir.mktmpdir }
  let(:binary) { ProfilerBinaryBuilder.vulnerable(dir) }

  it "fuzzes, trails the discovery and prints the triage facts" do
    trail = File.join(dir, "t.jsonl")
    out, _err, status = Open3.capture3(exe, "fuzz", binary, "-t", trail)
    expect(status.exitstatus).to eq(0)
    expect(out).to match(/fuzzed:\s+.*- \d+ crash/)
    expect(out).to include("triage:")
    expect(out).to include('vuln("sof")')

    events = File.readlines(trail).map { |l| JSON.parse(l) }
    expect(events.map { |e| e["type"] }).to include("fuzz", "triage")
  end

  it "is budgeted: --max-inputs caps the run" do
    trail = File.join(dir, "t.jsonl")
    _, _err, status = Open3.capture3(exe, "fuzz", binary, "--max-inputs", "10", "-t", trail)
    expect(status.exitstatus).to eq(0)
    event = JSON.parse(File.readlines(trail).first)
    expect(event["inputs"]).to eq(10)
  end
end
