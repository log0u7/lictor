# frozen_string_literal: true

require "augure"
require "securerandom"

module Lictor
  # The article's inversion: the agent enriches the fact base before the
  # reasoning, it never suggests verdicts. Suggestions pass the same
  # closed schema as any facts file (no applicable() exists to forge),
  # augure re-decides on the merged base, and the trail keeps who
  # proposed what and what actually changed - auditable hypotheses.
  module Suggestion
    module_function

    # base_facts / suggested: fact text. Returns the delta payload:
    # {facts:, added:, applicable_before:, applicable_after:,
    #  selected_before:, selected_after:} - and records a "suggest"
    # trail event. seed keeps the before/after comparison deterministic.
    def apply(base_facts:, suggested:, trail:, target:, seed: nil, packs: nil)
      base = Augure::Facts.parse(base_facts)
      delta = Augure::Facts.parse(suggested)
      suggested_tuples = delta.to_a
      existing = base.to_a

      before = Handoff.plan(facts: base_facts, seed: seed, packs: packs)
      # the LLM-only merge path: suggested facts carry :suggested provenance
      # so the corroboration gate cannot fire on them, and Facts#to_s keeps
      # the `// suggested` marker for the disk round-trip
      base.merge_suggested(suggested)
      after = Handoff.plan(facts: base, seed: seed, packs: packs)
      # what actually landed: new at parse time AND present after the merge
      # (the cap can drop facts; the trail must not report them as landed)
      added = suggested_tuples
        .reject { |rel, tuple| existing.include?([rel, tuple]) }
        .select { |rel, tuple| base[rel]&.include?(tuple) }

      trail.record(run: SecureRandom.uuid, type: "suggest", target: target,
        suggested: suggested_tuples, added: added,
        applicable_before: before[:applicable], applicable_after: after[:applicable],
        selected_before: before[:selected], selected_after: after[:selected])

      {
        facts: base, added: added,
        applicable_before: before[:applicable], applicable_after: after[:applicable],
        selected_before: before[:selected], selected_after: after[:selected]
      }
    end
  end
end
