# frozen_string_literal: true

require "open3"
require "json"
require "tmpdir"

RSpec.describe "bin/lictor rule" do
  let(:exe) { File.expand_path("../bin/lictor", __dir__) }
  let(:dir) { Dir.mktmpdir }
  let(:pack_path) do
    p = File.join(dir, "my_pack.yml")
    File.write(p, pack_yaml)
    p
  end
  let(:pack_yaml) do
    <<~YML
      technique: slow_ret2win
      author: claude-code (pack spec)
      source: https://example.com/writeup
      rules:
        - id: app_slow_ret2win
          head: [applicable, slow_ret2win]
          conditions:
            - [fact, vuln, sof]
            - [not_fact, relro, full]
      kb:
        - id: slow_ret2win_001
          technique: slow_ret2win
          description: a documented slow variant
          chain: [step]
          unlocks: [shell]
          success_rate: 0.5
      mcts:
        requires: []
        provides: []
        terminal: false
        success: 0.4
      priors: [3, 7]
    YML
  end

  it "validate: dry-runs the armor without installing" do
    out, _err, status = Open3.capture3(exe, "rule", "validate", pack_path, "-t", File.join(dir, "t.jsonl"))
    expect(status.exitstatus).to eq(0)
    expect(out).to include("pack:       slow_ret2win")
    expect(out).to include("corpus:     all 34 documented verdicts intact")
    expect(out).not_to include("installed")
  end

  it "install: interactive confirmation, copies and trails" do
    trail = File.join(dir, "t.jsonl")
    out, _err, status = Open3.capture3(exe, "rule", "install", pack_path,
      "--packs", File.join(dir, "packs"),
      "-t", trail, stdin_data: "slow_ret2win\n")
    expect(status.exitstatus).to eq(0)
    expect(out).to include("installed:")
    expect(File.exist?(File.join(dir, "packs/my_pack.yml"))).to be(true)
    event = JSON.parse(File.readlines(trail).last)
    expect(event["type"]).to eq("rule_install")
    expect(event["technique"]).to eq("slow_ret2win")
  end

  it "install: refuses a mismatched confirmation without installing" do
    _, err, status = Open3.capture3(exe, "rule", "install", pack_path,
      "--packs", File.join(dir, "packs"),
      "-t", File.join(dir, "t.jsonl"), stdin_data: "wrong\n")
    expect(status.exitstatus).not_to eq(0)
    expect(err).to include("confirmation mismatch")
    expect(Dir.exist?(File.join(dir, "packs"))).to be(false)
  end

  it "refuses a pack that fails the corpus guard" do
    hostile = File.join(dir, "hostile.yml")
    File.write(hostile, <<~YML)
      technique: greedy
      author: claude-code (pack spec)
      source: https://example.com/writeup
      rules:
        - id: app_greedy
          head: [applicable, greedy]
          conditions:
            - [fact, vuln, sof]
      kb:
        - id: greedy_001
          technique: greedy
          description: greedy everywhere
          chain: [step]
          unlocks: []
          success_rate: 0.5
      mcts:
        requires: []
        provides: []
        terminal: false
        success: 0.4
      priors: [100, 1]
    YML
    _out, err, status = Open3.capture3(exe, "rule", "validate", hostile)
    expect(status.exitstatus).not_to eq(0)
    expect(err).to include("corpus guard")
  end

  it "list: shows installed packs" do
    Open3.capture3(exe, "rule", "install", pack_path, "--packs", File.join(dir, "packs"),
      "-t", File.join(dir, "t.jsonl"), stdin_data: "slow_ret2win\n")
    out, _err, status = Open3.capture3(exe, "rule", "list", "--packs", File.join(dir, "packs"))
    expect(status.exitstatus).to eq(0)
    expect(out).to include("slow_ret2win")
  end
end
