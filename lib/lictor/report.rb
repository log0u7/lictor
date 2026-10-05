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

    def to_file(path, trail)
      File.write(path, from_trail(trail))
      path
    end
  end
end
