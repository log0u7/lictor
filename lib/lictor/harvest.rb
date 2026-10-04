# frozen_string_literal: true

require "socket"
require "securerandom"
require "augure"

module Lictor
  # The dynamic leak: the service PRINTS its own addresses. Connect,
  # capture what it says, parse the hex it hands over, and the facts
  # gain leaked_address(name, addr) - addresses OBSERVED LIVE,
  # provenance "observed-live". The banner_leak technique's engine.
  module Harvest
    class HarvestError < StandardError; end

    HEX = /0x([0-9a-f]{4,16})/i

    module_function

    # host[:port]. Returns {addresses:, facts:} - the facts text ready
    # to merge into the target's base.
    def harvest(target, trail:, timeout: 5, read_bytes: 512)
      host, port = target.split(":", 2)
      addresses = {}
      banner = ""
      Socket.tcp(host, port.to_i, connect_timeout: timeout) do |sock|
        begin
          sock.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
        rescue
          nil
        end
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
        loop do
          break if IO.select([sock], nil, nil, 0.5).nil?

          chunk = sock.read_nonblock(read_bytes, exception: false)
          break if chunk == "" # EOF: the socket will never yield more

          banner += chunk if chunk.is_a?(String)
          break if banner.bytesize >= read_bytes
          break if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
        end
      end
      banner.scan(HEX) do |hex|
        addr = hex.first.to_i(16)
        next if addr < 0x1000

        # name the leak: "win() at 0x..." -> the function whose call the
        # banner announced; the () between the name and the address is
        # skipped first, the plain preceding word is the fallback
        before = banner[0...Regexp.last_match.pre_match.length]
        name = before[/([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*[^\n]*\z/, 1] ||
          before[/([A-Za-z_][A-Za-z0-9_]*)\s*\z/, 1] ||
          "leak"
        addresses[name] ||= addr
      end
      raise HarvestError, "no address in the banner" if addresses.empty?

      facts = addresses.map { |name, addr| "leaked_address(\"#{name}\", #{addr})." }.join("\n") + "\n"
      trail.record(run: SecureRandom.uuid, type: "harvest", target: target,
        addresses: addresses.transform_values { |v| format("0x%x", v) })
      {addresses: addresses, facts: facts}
    rescue => e
      raise HarvestError, "the service said nothing readable: #{e.message}"
    end
  end
end
