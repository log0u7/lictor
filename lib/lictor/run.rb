# frozen_string_literal: true

require "securerandom"
require_relative "handoff"
require_relative "priors"
require_relative "trail"

module Lictor
  # The closed loop, driven: decide (augure) -> execute the plan's next
  # step (executor) -> outcome -> priors -> re-decide,
  # until a shell, or the budget runs out. Every step is trailed. The
  # handoff executor makes the whole loop safe by construction: it
  # "executes" by printing.
  module Run
    module_function

    def run(target:, facts:, trail:, executor: nil, max_attempts: 3,
      seed: nil, priors: nil, packs: nil, payload: nil, binary: nil, repo_dir: nil)
      executor ||= ManualExecutor.new
      attempts = []

      # The static read feeds the decision: the sink the frame analysis
      # found (strcpy/gets...) becomes the vuln_hint the engine derives
      # from, the winning symbol's existence becomes the target fact.
      # Measurement -> decision, in one trail.
      if binary
        begin
          static = AugureProfiler::StaticOffset.offset(binary)
          enriched = +facts.to_s
          enriched << "vuln_hint(\"unsafe_func:#{static[:sink]}\").\n" if static[:sink]
          enriched << "target_function(\"true\").\n" if facts.include?("win_symbol(") && static[:sink]
          facts = enriched if enriched != facts
        rescue
          # the static read is an enrichment, never a gate
        end
      end

      max_attempts.times do
        decision = Handoff.plan(facts: facts, seed: seed, priors: Priors.from_trail(trail), packs: packs)
        technique = decision[:selected]
        break if technique.nil?

        result = executor.execute(target: target, technique: technique,
          recipe: decision[:recipe], payload: payload)
        # The repos have no exploit for the decided technique and the
        # binary is in hand: scaffold it (measured constants), trail it,
        # and the NEXT attempt discovers it. The operator still reviews
        # the file - the loop does not invent craft, it drafts it.
        if !result[:executed] && binary && repo_dir
          build = PayloadBuilder.build(binary: binary, facts: facts,
            technique: technique, out: File.join(repo_dir, "payload.bin"))
          dest = ExploitScaffold.scaffold(technique: technique, constants: build,
            repo_dir: repo_dir, author: "lictor run auto-scaffold")
          trail.record(run: SecureRandom.uuid, type: "scaffold", technique: technique,
            offset: build[:offset], offset_source: build[:offset_source],
            ret: build[:ret_source], file: dest)
        end
        attempt = {
          technique: technique, executed: result[:executed],
          success: result[:success], exploit: result[:exploit], handoff: result[:handoff]
        }
        attempts << attempt
        trail.record(run: SecureRandom.uuid, type: "outcome", technique: technique,
          success: result[:success] == true, executed: result[:executed],
          target: target)
        break if result[:success] == true

        # Failed execution: avoid repeating the same technique with the
        # same evidence - the failed outcome feeds the priors next round.
      end

      status = if attempts.any? && attempts.last[:success] == true
        "success"
      else
        "budget-exhausted"
      end
      {status: status, steps: attempts}
    end
  end
end
