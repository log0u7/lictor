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

    # Plan and outcome events grouped per run, in run order.
    def runs
      grouped = {}
      events.each do |event|
        run = grouped[event["run"]] ||= {run: event["run"], outcomes: []}
        case event["type"]
        when "plan"
          run.merge!(event.slice("mode", "selected", "applicable", "explain",
            "facts_file", "profiled", "priors_adapted")
                         .transform_keys(&:to_sym))
        when "profile"
          run[:profiled] = event["binary"]
        when "outcome"
          run[:outcomes] << {technique: event["technique"], success: event["success"]}
        when "scan"
          run[:scanned] = event["target"]
        end
      end
      grouped.values
    end
  end
end
