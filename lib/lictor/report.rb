# frozen_string_literal: true

module Lictor
  # The engagement report: the auditable deliverable. Every run - the
  # decision, the rule provenance behind it, the handoff recipe, the
  # outcome - rendered as markdown a client can read. Predictions stay
  # labeled as predictions.
  module Report
    module_function

    def from_trail(trail)
      lines = []
      lines << "# Engagement report"
      lines << ""
      lines << "generated: #{Time.now.utc.iso8601}"
      lines << ""
      lines << "_All numbers below are model predictions with rule provenance, not field results._"
      lines << ""

      trail.runs.each do |run|
        lines << "## Run `#{run[:run]}`"
        lines << ""
        lines << "- scan: #{run[:scanned]} (nmap)" if run[:scanned]
        lines << "- acquire: #{run[:acquired]}" if run[:acquired]
        if (built = run[:built])
          lines << "- build: #{built[:technique]}, offset #{built[:offset]} (#{built[:ret]}), #{built[:size]} bytes -> #{built[:out]}"
        end
        lines << "- scaffold: #{run[:scaffolded]}" if run[:scaffolded]
        lines << "- harvest: #{run[:harvested]}" if run[:harvested]
        lines << "- verify: the remote #{run[:verified] ? "faulted" : "survived"}" unless run[:verified].nil?
        lines << "- suggest: #{run[:suggested]} added" if run[:suggested]
        lines << "- leak: #{run[:leaked]}" if run[:leaked]
        if (measured = run[:measured])
          lines << "- measure: the sink #{measured[:sink]} at offset #{measured[:offset]} (#{measured[:source]})"
        end
        lines << "- drafted: the pack #{run[:drafted]} (staging)" if run[:drafted]
        lines << "- fuzz: #{run[:fuzzed]} (#{run[:crashes]} crashes)" if run[:fuzzed]
        lines << "- mode: #{run[:mode]}" if run[:mode]
        lines << "- facts: #{run[:facts_file]}" if run[:facts_file]
        lines << "- applicable: #{Array(run[:applicable]).join(", ")}" if run[:applicable]
        lines << "- selected: **#{run[:selected]}**" if run[:selected]
        if (explain = run[:explain])
          provs = explain[:provenance] || explain["provenance"] || {}
          entries = provs[run[:selected]] || provs[run[:selected].to_s] || []
          entries.each do |p|
            evidence = (p[:evidence] || p["evidence"]).map { |e| e.join("=") }.join(", ")
            lines << "  - #{run[:selected]} <- #{p[:rule] || p["rule"]} (#{evidence})"
          end
        end
        Array(run[:outcomes]).each do |o|
          verdict = o[:success] ? "success" : "failure"
          lines << "- outcome: **#{verdict}** (#{o[:technique]})"
        end
        lines << ""
      end
      lines.join("\n")
    end

    # The defender view: the trail read from the BLUE side - the raw
    # action timeline (what the operator did) plus, per attempted
    # technique, the pack's detection: hints (the observables the
    # defenses should have seen). The same JSONL feeds both sides.
    def defender(trail, packs: [])
      hints = Array(packs).flat_map do |p|
        Array(p.detection).map { |d| [p.technique, d] }
      end.group_by { |tech, _| tech }

      lines = []
      lines << "# Defender report (the trail read backwards)"
      lines << ""
      lines << "generated: #{Time.now.utc.iso8601}"
      lines << ""
      lines << "_Built from the same append-only trail the operator's report reads._"
      lines << ""

      lines << "## The action timeline"
      lines << ""
      trail.events.each do |event|
        type = event["type"]
        what = case type
        when "scan" then "scanned #{event["target"]} (nmap)"
        when "harvest" then "harvest the banner of #{event["target"]} - addresses read: #{event["addresses"].keys.join(", ")}"
        when "verify" then "verified the remote faults like the local model: #{event["target"]}"
        when "outcome" then "attempted #{event["technique"]} against #{event["target"]} (#{event["success"] ? "success" : "failed"})"
        when "leak" then "captured leaks: #{event["addresses"].keys.join(", ")}"
        when "fuzz" then "fuzzed #{event["binary"]}"
        when "build" then "built the payload for #{event["technique"]} (offset #{event["offset"]})"
        end
        next unless what

        lines << "- #{event["timestamp"]}: #{what}"
      end

      attempted = trail.events.select { |e| e["type"] == "outcome" }.map { |e| e["technique"] }.uniq
      if attempted.empty?
        return lines.join("
")
      end

      lines << ""
      lines << "## The detection hints for the attempted techniques"
      lines << ""
      attempted.each do |tech|
        entries = hints[tech]
        lines << "### #{tech}"
        if entries
          entries.each do |(_t, d)|
            lines << "- #{d["channel"]}: #{d["signature"]} - #{d["note"]}"
          end
        else
          lines << "- no detection hints (teach the pack: the detection: section)"
        end
      end
      lines.join("
")
    end

    def to_file(path, trail)
      File.write(path, from_trail(trail))
      path
    end
  end
end
