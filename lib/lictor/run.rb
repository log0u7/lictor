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
      seed: nil, priors: nil, packs: nil, payload: nil, binary: nil, repo_dir: nil,
      flag_regex: nil)
      executor ||= ManualExecutor.new
      attempts = []
      leaks = {}
      scaffolded_techniques = []

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
          recipe: decision[:recipe], payload: payload, flag_regex: flag_regex)
        # The leak capture: the service's own output hex addresses
        # become leaked_address facts for the NEXT attempt (the
        # two-steps: leak, then rebuild with the observed values). The
        # facts the build layouts resolve as leak:NAME.
        if result[:output].is_a?(String) && !result[:output].empty?
          found = Harvest.parse_banner(result[:output]).reject { |name, _| leaks.key?(name) }
          unless found.empty?
            leaks.merge!(found)
            facts = Augure::Facts.parse(facts.to_s + found.map { |name, addr|
              "leaked_address(\"#{name}\", #{addr})."
            }.join("\n") + "\n")
            trail.record(run: SecureRandom.uuid, type: "leak", target: target,
              addresses: found.transform_values { |v| format("0x%x", v) })
          end
        end

        # The repos have no exploit for the decided technique and the
        # binary is in hand: scaffold it (measured constants), trail it,
        # and the NEXT attempt discovers it. The operator still reviews
        # the file - the loop does not invent craft, it drafts it.
        scaffolded_now = false
        if !result[:executed] && binary && repo_dir && !scaffolded_techniques.include?(technique)
          build = PayloadBuilder.build(binary: binary, facts: facts,
            technique: technique, out: File.join(repo_dir, "payload.bin"))
          dest = ExploitScaffold.scaffold(technique: technique, constants: build,
            repo_dir: repo_dir, author: "lictor run auto-scaffold")
          trail.record(run: SecureRandom.uuid, type: "scaffold", technique: technique,
            offset: build[:offset], offset_source: build[:offset_source],
            ret: build[:ret_source], file: dest)
          scaffolded_now = true
          scaffolded_techniques << technique
        end
        attempt = {
          technique: technique, executed: result[:executed],
          success: result[:success], exploit: result[:exploit], handoff: result[:handoff]
        }
        attempts << attempt
        # The outcome feeds the priors ONLY when something actually ran:
        # a handoff attempt (the safe default) never attempted anything,
        # and recording it as a failure systematically downgrades the
        # decided technique for every future decision.
        if result[:executed]
          trail.record(run: SecureRandom.uuid, type: "outcome", technique: technique,
            success: result[:success] == true, executed: true,
            target: target)
        end
        break if result[:success] == true

        # Failed execution: avoid repeating the same technique with the
        # same evidence - the failed outcome feeds the priors next round.
        # A handoff also stops: the recipe is identical, nothing was
        # attempted. But a fresh auto-scaffold CHANGED the repos: the
        # next attempt discovers it, so the loop continues.
        break unless result[:executed] || scaffolded_now
      end

      status = if attempts.any? && attempts.last[:success] == true
        "success"
      elsif attempts.any? && attempts.none? { |a| a[:executed] }
        "handoff"
      else
        "budget-exhausted"
      end
      {status: status, steps: attempts, leaks: leaks}
    end
  end
end
