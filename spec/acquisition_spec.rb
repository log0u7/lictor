# frozen_string_literal: true

require "lictor"
require "json"
require "tmpdir"
require "open3"
require "fileutils"

builder = ["../../augure/profiler/spec/support/binary_builder.rb",
  "../augure/profiler/spec/support/binary_builder.rb"]
  .map { |p| File.expand_path(p, __dir__) }
  .find { |p| File.file?(p) }
require_relative builder

RSpec.describe Lictor::Acquisition do
  let(:dir) { Dir.mktmpdir }
  let(:binary) { ProfilerBinaryBuilder.vulnerable(dir) }
  let(:trail) { Lictor::Trail.new(File.join(dir, "t.jsonl")) }

  it "acquires from a local path, profiles and trails" do
    result = described_class.acquire("127.0.0.1:9999", source: "local:#{binary}",
      trail: trail, out_dir: dir)
    expect(result[:facts]).to include("nx(")
    expect(File.exist?(File.join(dir, "target.facts"))).to be(true)
    event = JSON.parse(File.readlines(File.join(dir, "t.jsonl")).last)
    expect(event["type"]).to eq("acquire")
    expect(event["source"]).to start_with("local:")
  end

  it "profiles the companion library and merges its facts" do
    lib = ProfilerBinaryBuilder.vulnerable(dir)
    lib_name = "lib#{File.basename(binary)}.so"
    FileUtils.cp(lib, File.join(File.dirname(binary), lib_name))
    result = described_class.acquire("127.0.0.1:9999", source: "local:#{binary}",
      trail: trail, out_dir: dir)
    # the lib's own facts ride the merged file (the vulnerable builder
    # binary carries the strcpy sink fact)
    facts = File.read(result[:facts_path])
    expect(facts.scan('vuln("sof")').size).to be >= 2
  end

  it "stays silent when no companion library exists" do
    result = described_class.acquire("127.0.0.1:9999", source: "local:#{binary}",
      trail: trail, out_dir: dir)
    facts = File.read(result[:facts_path])
    expect(facts.scan('vuln("sof")').size).to eq(1)
  end

  it "skips a companion library the profiler cannot read" do
    lib_name = "lib#{File.basename(binary)}.so"
    File.binwrite(File.join(File.dirname(binary), lib_name), "\x7fELF" + "\x00" * 32)
    result = described_class.acquire("127.0.0.1:9999", source: "local:#{binary}",
      trail: trail, out_dir: dir)
    facts = File.read(result[:facts_path])
    expect(facts.scan('vuln("sof")').size).to eq(1)
  end

  it "acquires over http (stdlib net/http against a fixture server)" do # A tiny fixture server serving the binary.
    server = TCPServer.new("127.0.0.1", 0)
    port = server.addr[1]
    thread = Thread.new do
      loop do
        client = server.accept
        req = +""
        req << client.readpartial(4096) until req.include?("\r\n\r\n")
        body = File.binread(binary)
        client.write("HTTP/1.1 200 OK\r\nContent-Length: #{body.bytesize}\r\n\r\n#{body}")
        client.close
      rescue
        break
      end
    end
    result = described_class.acquire("127.0.0.1:#{port}",
      source: "http://127.0.0.1:#{port}/vuln_service",
      trail: trail, out_dir: dir)
    expect(result[:facts]).to include("nx(")
    expect(result[:binary_path]).to include("vuln_service")
    thread.kill
  end

  it "refuses a non-ELF payload with the service-facts guidance" do
    path = File.join(dir, "notelf.txt")
    File.write(path, "just some text")
    expect do
      described_class.acquire("127.0.0.1:9999", source: "local:#{path}",
        trail: trail, out_dir: dir)
    end.to raise_error(Lictor::AcquisitionError, /not an ELF|service packs|service facts/i)
  end

  it "surfaces the profiler stderr when profiling fails" do
    bad = File.join(dir, "bad_profiler")
    File.write(bad, "#!/bin/sh\necho 'augure-profile: boom: parse error' >&2\nexit 1\n")
    File.chmod(0o755, bad)
    expect do
      described_class.acquire("127.0.0.1:9999", source: "local:#{binary}",
        trail: trail, out_dir: dir, profiler_cmd: bad)
    end.to raise_error(Lictor::AcquisitionError, /boom: parse error/)
  end
end
