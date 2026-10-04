# frozen_string_literal: true

require "json"
require "open3"
require "tmpdir"
require "lictor-mcp"

RSpec.describe LictorMcp::Server do
  let(:server) { described_class.build }

  def rpc(id, tool, args)
    %( {"jsonrpc":"2.0","id":#{id},"method":"tools/call","params":{"name":"#{tool}","arguments":#{JSON.generate(args)}}} ) + "\n"
  end

  it "exposes the seven tools" do
    expect(server.tools.values.map(&:tool_name))
      .to contain_exactly("scan_target", "plan_technique", "execute_technique", "validate_pack",
        "suggest_facts", "build_payload", "scaffold_exploit")
  end

  it "plan emits the decision with provenance" do
    dir = Dir.mktmpdir
    list = File.join(dir, "targets.yml")
    File.write(list, "192.168.56.10\n")
    facts = File.join(dir, "target.facts")
    File.write(facts, "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\nplt(\"system\").\n" \
                      "gadget(\"pop_rdi_ret\", 1).\nvuln_hint(\"unsafe_func:gets\").\n")
    response = server.handle_json(rpc(1, "plan_technique", {target: facts}))
    decision = JSON.parse(JSON.parse(response).dig("result", "content", 0, "text"))
    expect(decision["selected"] || decision[:selected]).to eq("ret2plt")
  end

  it "suggest_facts returns the decision delta and refuses off-schema facts" do
    dir = Dir.mktmpdir
    list = File.join(dir, "targets.yml")
    File.write(list, "192.168.56.10\n")
    facts = File.join(dir, "target.facts")
    File.write(facts, "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\n")
    response = server.handle_json(rpc(1, "suggest_facts", {
      facts_path: facts,
      suggested_facts: "plt(\"system\").\ngadget(\"pop_rdi_ret\", 1).\nvuln_hint(\"unsafe_func:gets\").\n"
    }))
    delta = JSON.parse(JSON.parse(response).dig("result", "content", 0, "text"))["delta"]
    expect(delta["added"].size).to eq(3)
    expect(delta["applicable_after"]).to include("ret2plt")

    forged = server.handle_json(rpc(2, "suggest_facts", {
      facts_path: facts, suggested_facts: "applicable(ret2plt).\n"
    }))
    expect(JSON.parse(forged).dig("result", "content", 0, "text")).to include("unknown predicate")
  end

  it "build_payload builds, trails and returns the measurement" do
    builder = ["../../augure/profiler/spec/support/binary_builder.rb",
      "../augure/profiler/spec/support/binary_builder.rb"]
      .map { |p| File.expand_path(p, __dir__) }
      .find { |p| File.file?(p) }
    require_relative builder
    dir = Dir.mktmpdir
    list = File.join(dir, "targets.yml")
    File.write(list, "192.168.56.10\n")
    facts = File.join(dir, "target.facts")
    File.write(facts, "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\n" \
      "win_symbol(\"win\", 4196182).\ngadget(\"ret_align\", 4196100).\n")
    binary = ProfilerBinaryBuilder.vulnerable
    response = server.handle_json(rpc(1, "build_payload", {
      binary: binary, facts_path: facts, technique: "ret2func"
    }))
    payload = JSON.parse(JSON.parse(response).dig("result", "content", 0, "text"))
    expect(payload["offset"]).to eq(16)
    expect(payload["offset_source"]).to eq("static-frame")
    expect(payload["ret_source"]).to include("win_symbol:win")
  end

  it "scaffold_exploit lands the draft in the staging dir" do
    builder = ["../../augure/profiler/spec/support/binary_builder.rb",
      "../augure/profiler/spec/support/binary_builder.rb"]
      .map { |p| File.expand_path(p, __dir__) }
      .find { |p| File.file?(p) }
    require_relative builder
    dir = Dir.mktmpdir
    list = File.join(dir, "targets.yml")
    File.write(list, "192.168.56.10\n")
    facts = File.join(dir, "target.facts")
    File.write(facts, "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\n" \
      "win_symbol(\"win\", 4196182).\ngadget(\"ret_align\", 4196100).\n")
    binary = ProfilerBinaryBuilder.vulnerable
    staging = File.join(dir, "staging")
    FileUtils.mkdir_p(staging)
    response = server.handle_json(rpc(2, "scaffold_exploit", {
      binary: binary, facts_path: facts, technique: "ret2func",
      staging_dir: staging
    }))
    payload = JSON.parse(JSON.parse(response).dig("result", "content", 0, "text"))
    expect(payload["scaffolded"]).to match(/lab_ret2func_001\.rb\z/)
    expect(File.read(payload["scaffolded"])).to include("MEASURED (static-frame)")
  end

  it "validate_pack accepts the canon pack (sibling checkout)" do
    canon = ["../../augure/packs/ret2csu_v2.yml", "../augure/packs/ret2csu_v2.yml"]
      .map { |p| File.expand_path(p, __dir__) }
      .find { |p| File.file?(p) }
    skip "augure canon pack not found" unless canon
    response = server.handle_json(rpc(1, "validate_pack", {pack_path: canon}))
    payload = JSON.parse(JSON.parse(response).dig("result", "content", 0, "text"))
    expect(payload["valid"]).to be(true)
  end
end
