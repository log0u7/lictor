# frozen_string_literal: true

require "lictor"
require "tmpdir"
require "fileutils"

RSpec.describe "installed packs influence decisions" do
  let(:dir) { Dir.mktmpdir }
  let(:trail) { Lictor::Trail.new(File.join(dir, "t.jsonl")) }
  let(:packs_dir) do
    canon = ["../../augure/packs/ret2csu_v2.yml", "../augure/packs/ret2csu_v2.yml"]
      .map { |p| File.expand_path(p, __dir__) }
      .find { |p| File.file?(p) }
    skip "augure canon pack not found" unless canon
    d = File.join(dir, "packs")
    FileUtils.mkdir_p(d)
    FileUtils.cp(canon, d)
    d
  end
  let(:csu_facts) do
    "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\n" \
      "gadget(\"csu_popper\", 1).\ngadget(\"csu_mov\", 2).\nvuln_hint(\"unsafe_func:gets\").\n"
  end

  it "TechniquePacks.load returns [] when the directory is absent or nil" do
    expect(Lictor::TechniquePacks.load(nil)).to eq([])
    expect(Lictor::TechniquePacks.load(File.join(dir, "missing"))).to eq([])
  end

  it "TechniquePacks.load refuses a pack that breaks the corpus" do
    bad = File.join(dir, "hostile.yml")
    File.write(bad, <<~YAML)
      technique: hostile
      author: attacker
      source: nowhere
      rules:
        - id: app_hostile
          head: [applicable, hostile]
          conditions:
            - [fact, nx, true]
      kb: []
      mcts:
        requires: []
        provides: []
        terminal: true
        success: 0.5
      priors: [500, 1]
    YAML
    expect { Lictor::TechniquePacks.load(File.dirname(bad), guard: true) }
      .to raise_error(Augure::PackError)
  end

  it "Handoff.plan(packs:) ranks the pack technique with its provenance" do
    without_packs = Lictor::Handoff.plan(facts: csu_facts, seed: 42)
    expect(without_packs[:applicable]).not_to include("ret2csu_v2")

    with_packs = Lictor::Handoff.plan(facts: csu_facts, seed: 42,
      packs: Lictor::TechniquePacks.load(packs_dir))
    expect(with_packs[:applicable]).to include("ret2csu_v2")
    expect(with_packs[:explain][:provenance]["ret2csu_v2"].first[:origin]).to eq("ret2csu_v2")
  end

  it "Run.run carries packs into the loop" do
    # brop fires ONLY through a pack rule (no built-in rule reads
    # remote/verified) - an unambiguous proof the loop saw the pack.
    brop_facts = "remote(\"true\").\nverified(\"remote\").\nnx(\"true\").\n"
    token = Lictor::Consent.issue(trail, "192.168.56.10", confirm_input: "192.168.56.10\n")
    executor = Class.new do
      def execute(target:, technique:, recipe:, exploit_name: nil)
        {executed: true, success: true, technique: technique}
      end
    end
    result = Lictor::Run.run(target: "192.168.56.10", facts: brop_facts, trail: trail,
      executor: executor.new, consent_token: token, seed: 42,
      packs: Lictor::TechniquePacks.load(File.expand_path("../../augure/packs", __dir__)))
    expect(result[:steps].first[:technique]).to eq("brop")
  end

  it "the MCP plan tool picks up the packs directory from the project config" do
    require "lictor-mcp"
    canon = File.expand_path("../augure/packs/ret2csu_v2.yml", __dir__)
    skip "augure canon pack not found" unless File.file?(canon)
    project = Dir.mktmpdir
    FileUtils.mkdir_p(File.join(project, "packs"))
    FileUtils.cp(canon, File.join(project, "packs"))
    File.write(File.join(project, "lictor.yml"), {packs: "packs"}.to_yaml)
    list = File.join(project, "targets.yml")
    File.write(list, "192.168.56.10\n")
    facts = File.join(project, "target.facts")
    File.write(facts, csu_facts)
    Dir.chdir(project) do
      response = LictorMcp::Server.build.handle_json(
        %( {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"plan_technique","arguments":#{JSON.generate({target: facts, allowlist: list})}}} ) + "\n"
      )
      decision = JSON.parse(JSON.parse(response).dig("result", "content", 0, "text"))
      expect(decision["applicable"]).to include("ret2csu_v2")
    end
  end
end
