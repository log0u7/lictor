# frozen_string_literal: true

require "socket"

module Lictor
  class TubeError < StandardError; end

  # The ONE TCP implementation behind the banner readers (harvest,
  # verify): connect, read_until (EOF/reset/deadline/limit), write,
  # reset tracking, close. The run channel stays the ronin subprocess
  # (ADR 0001's honest boundary).
  # UDP, TLS and HTTP-aware delivery become flavors of the same seam
  # (ADR lictor 0001). The timeout/deadline semantics live here, once.
  class Tube
    attr_reader :reset_seen

    def self.tcp(host, port, timeout: 5)
      sock = Socket.tcp(host, port.to_i, connect_timeout: timeout)
      new(sock, deadline: Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout)
    rescue SystemCallError => e
      raise TubeError, "connect #{host}:#{port} failed: #{e.message}"
    end

    def initialize(sock, deadline:)
      @sock = sock
      @deadline = deadline
      @reset_seen = false
    end

    # Read until the connection dies (EOF or reset), the deadline or the
    # limit; returns everything captured. A reset is recorded, not
    # raised: the callers' crash heuristics need the distinction.
    def read_bytes(limit: 512)
      reply = +""
      loop do
        break if reply.bytesize >= limit
        break if Process.clock_gettime(Process::CLOCK_MONOTONIC) > @deadline

        chunk = @sock.read_nonblock(limit - reply.bytesize, exception: false)
        case chunk
        # nil: read_nonblock(exception: false) signals EOF as nil, "" as
        # a truly empty read - both mean the socket will yield no more
        when "", nil then break
        when :wait_readable
          break unless IO.select([@sock], nil, nil, 0.5)
        else
          reply << chunk
        end
      end
      reply
    rescue Errno::ECONNRESET, Errno::EPIPE
      @reset_seen = true
      reply
    end

    def gets(delim = "\n", wait: 2)
      @sock.wait_readable(wait) ? @sock.gets(delim) : nil
    end

    def write(data)
      @sock.write(data)
      self
    rescue Errno::EPIPE, Errno::ECONNRESET
      @reset_seen = true
      self
    end

    def close
      @sock.close unless @sock.closed?
    rescue IOError, Errno::ENOTCONN
      nil
    end

    def reset? = @reset_seen
  end
end
