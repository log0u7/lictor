# frozen_string_literal: true

require "json"
require "time"

module Lictor
  # Append-only JSONL trail: one line per event, timestamped. An engagement
  # you cannot replay is an engagement you cannot defend. (SQLite/sequel
  # comes when queries are actually needed; JSONL is the honest v1.)
  class Trail
    def initialize(path)
      @path = path
    end

    def record(event)
      line = JSON.generate(event.merge(timestamp: Time.now.utc.iso8601))
      File.open(@path, "a") { |f| f.puts(line) }
      self
    end

    def events
      File.readlines(@path).map { |l| JSON.parse(l) }
    rescue Errno::ENOENT
      []
    end
  end
end
