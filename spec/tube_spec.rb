# frozen_string_literal: true

require "lictor"
require "socket"
require "tmpdir"

# The one TCP implementation behind the banner readers (ADR lictor 0001):
# connect, read_until, sendline, close - the seam UDP/TLS/HTTP plug into.
RSpec.describe Lictor::Tube do
  # a reliable RST: linger 0 with pending data kills the connection hard
  def abrupt_server(payload)
    server = TCPServer.new("127.0.0.1", 0)
    port = server.addr[1]
    th = Thread.new do
      cli = server.accept
      cli.write(payload) if payload
      cli.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack("l_2"))
      cli.close
    rescue
      nil
    end
    [server, port, th]
  end

  def polite_server(payload)
    server = TCPServer.new("127.0.0.1", 0)
    port = server.addr[1]
    th = Thread.new do
      cli = server.accept
      cli.write(payload) if payload
      cli.close_write
      cli.close
    rescue
      nil
    end
    [server, port, th]
  end

  it "reads until the polite EOF and reports no reset" do
    server, port, th = polite_server("win() at 0x401260\n")
    tube = described_class.tcp("127.0.0.1", port, timeout: 5)
    reply = tube.read_bytes(limit: 512)
    tube.close
    th.join(2)
    server.close
    expect(reply).to include("0x401260")
    expect(tube.reset_seen).to be(false)
  end

  it "survives an abrupt reset and reports it" do
    server, port, th = abrupt_server("hello\n")
    tube = described_class.tcp("127.0.0.1", port, timeout: 5)
    reply = tube.read_bytes(limit: 512)
    tube.close
    th.join(2)
    server.close
    expect(reply).to include("hello")
    expect(tube.reset_seen).to be(true)
  end

  it "honors the deadline when the service says nothing" do
    server = TCPServer.new("127.0.0.1", 0)
    port = server.addr[1]
    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    tube = described_class.tcp("127.0.0.1", port, timeout: 1)
    reply = tube.read_bytes(limit: 512)
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0
    tube.close
    server.close
    expect(reply).to eq("")
    expect(elapsed).to be_between(0.5, 3.0)
  end

  it "sendline carries the newline and writes the payload bytes" do
    server = TCPServer.new("127.0.0.1", 0)
    port = server.addr[1]
    th = Thread.new do
      cli = server.accept
      data = cli.read(10)
      cli.write("got:#{data.unpack1("H*")}")
      cli.close
    rescue
      nil
    end
    tube = described_class.tcp("127.0.0.1", port, timeout: 5)
    tube.write("1234567890")
    reply = tube.read_bytes(limit: 64)
    tube.close
    th.join(2)
    server.close
    expect(reply).to include("31323334353637383930")
  end
end
