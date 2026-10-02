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

  it "exposes the four gated tools" do
    expect(server.tools.values.map(&:tool_name))
      .to contain_exactly("scan_target", "plan_technique", "execute_technique", "validate_pack")
  end

  it "scan refuses a host outside the allowlist (server-side gate)" do
    dir = Dir.mktmpdir
    list = File.join(dir, "targets.yml")
    File.write(list, "192.168.56.10\n")
    response = server.handle_json(rpc(1, "scan_target", {host: "10.9.9.9", allowlist: list}))
    text = JSON.parse(response).dig("result", "content", 0, "text")
    expect(text).to include("UNAUTHORIZED")
  end

  it "execute refuses an invalid consent token" do
    dir = Dir.mktmpdir
    list = File.join(dir, "targets.yml")
    File.write(list, "192.168.56.10\n")
    response = server.handle_json(rpc(1, "execute_technique", {
      target: "192.168.56.10", technique: "ret2plt", exploit_name: "lab_ret2plt_001",
      consent_token: "forged", allowlist: list
    }))
    text = JSON.parse(response).dig("result", "content", 0, "text")
    expect(text).to include("consent token invalid")
  end

  it "plan emits the decision with provenance" do
    dir = Dir.mktmpdir
    list = File.join(dir, "targets.yml")
    File.write(list, "192.168.56.10\n")
    facts = File.join(dir, "target.facts")
    File.write(facts, "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\nplt(\"system\").\n" \
                      "gadget(\"pop_rdi_ret\", 1).\nvuln_hint(\"unsafe_func:gets\").\n")
    response = server.handle_json(rpc(1, "plan_technique", {target: facts, allowlist: list}))
    decision = JSON.parse(JSON.parse(response).dig("result", "content", 0, "text"))
    expect(decision["selected"] || decision[:selected]).to eq("ret2plt")
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
