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
      suggested_facts = Augure::Facts.parse(suggested)
      added = suggested_facts.to_a.reject { |rel, tuple| base[rel]&.include?(tuple) }

      before = Handoff.plan(facts: base_facts, seed: seed, packs: packs)
      merged = base.merge(suggested_facts)
      after = Handoff.plan(facts: merged, seed: seed, packs: packs)

      trail.record(run: SecureRandom.uuid, type: "suggest", target: target,
        suggested: suggested_facts.to_a, added: added,
        applicable_before: before[:applicable], applicable_after: after[:applicable],
        selected_before: before[:selected], selected_after: after[:selected])

      {
        facts: merged, added: added,
        applicable_before: before[:applicable], applicable_after: after[:applicable],
        selected_before: before[:selected], selected_after: after[:selected]
      }
    end
  end
end
