# frozen_string_literal: true

require "lictor"
require "json"
require "tmpdir"
require "open3"

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

  it "acquires over http (stdlib net/http against a fixture server)" do
    # A tiny fixture server serving the binary.
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
    expect {
      described_class.acquire("127.0.0.1:9999", source: "local:#{path}",
        trail: trail, out_dir: dir)
    }.to raise_error(Lictor::AcquisitionError, /not an ELF|service packs|service facts/i)
  end
end
