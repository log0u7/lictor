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
      # 0600 at creation: the record of offensive operations is private
      # from birth (existing files keep the operator's perms)
      File.open(@path, "a", 0o600) { |f| f.puts(line) }
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
          run[:outcomes] << {technique: event["technique"], success: event["success"],
                             executed: event["executed"] || false}
        when "scan"
          run[:scanned] = event["target"]
        when "fuzz"
          run[:fuzzed] = event["binary"]
          run[:crashes] = event["crashes"]
        when "triage"
          run[:triage] = {signal: event["signal"], control: event["control"]}
        when "rule_install"
          run[:taught] = event["technique"]
        when "acquire"
          run[:acquired] = event["binary"]
        when "build"
          run[:built] = {technique: event["technique"], offset: event["offset"],
                         ret: event["ret"], size: event["size"], out: event["out"]}
        when "scaffold"
          run[:scaffolded] = event["file"]
        when "harvest"
          run[:harvested] = event["addresses"]
        when "verify"
          run[:verified] = event["remote_crashed"]
        when "suggest"
          run[:suggested] = event["added"]
        when "leak"
          run[:leaked] = event["addresses"]
        when "measure"
          run[:measured] = {sink: event["sink"], offset: event["offset"], source: event["source"]}
        when "pack_draft"
          run[:drafted] = event["technique"]
        end
      end
      grouped.values
    end
  end
end
