# frozen_string_literal: true

require "json"
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
  class RunError < StandardError; end

  module Run
    module_function

    def run(target:, facts:, trail:, executor: nil, max_attempts: 3,
      seed: nil, priors: nil, packs: nil, payload: nil, binary: nil, repo_dir: nil,
      flag_regex: nil, manifest_path: nil, resume: nil)
      executor ||= ManualExecutor.new
      attempts = []
      leaks = {}
      scaffolded_techniques = []

      # The run manifest (ADR 0003): one stable id per logical run, the
      # state (facts with the merged leaks, the attempt history) written
      # per attempt. --resume <id> continues THAT run - an interruption
      # is a pause, not an orphan.
      if resume
        unless manifest_path && File.file?(manifest_path)
          raise RunError,
            "resume needs a manifest (run with manifest_path first)"
        end

        manifest = JSON.parse(File.read(manifest_path))
        raise RunError, "the manifest holds run #{manifest["id"]}, not #{resume}" if manifest["id"] != resume

        run_id = manifest["id"]
        facts = manifest["facts"]
        start = manifest["attempts"].size
      else
        run_id = SecureRandom.uuid
        start = 0
      end

      # per-attempt persistence: an interruption is a pause, not an
      # orphan - the state (facts with the merged leaks, the attempt
      # history) lands on disk after every event
      write_manifest = lambda do |status|
        next unless manifest_path

        File.write(manifest_path,
          JSON.generate(id: run_id, target: target, status: status,
            attempts: attempts, facts: facts.to_s))
      end

      # The static read feeds the decision: the sink the frame analysis
      # found (strcpy/gets...) becomes the vuln_hint the engine derives
      # from, the winning symbol's existence becomes the target fact.
      # Measurement -> decision, in one trail.
      if binary
        begin
          require "augure-profiler" # lazy: the enrichment loads metasm
          static = AugureProfiler::StaticOffset.offset(binary)
          # the static read is TRAILED: the measure -> decision chain is
          # auditable, and a swallowed error class (a NameError hiding
          # under a bare rescue) cannot hide - the event's absence is
          # the test's red flag
          trail.record(run: run_id, type: "measure", target: target,
            sink: static[:sink], offset: static[:offset], source: "static-frame")
          enriched = +facts.to_s
          enriched << "vuln_hint(\"unsafe_func:#{static[:sink]}\").\n" if static[:sink]
          enriched << "target_function(\"true\").\n" if facts.include?("win_symbol(") && static[:sink]
          facts = enriched if enriched != facts
        rescue Metasm::DecodeError, Metasm::ParseError, Metasm::InvalidExeFormat,
          Errno::ENOENT, Errno::EACCES
          # the static read is an enrichment, never a gate - the
          # KNOWN failure modes only: a programming error (NameError,
          # NoMethodError) must crash loudly, not vanish here
        end
      end

      (start...max_attempts).each do
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
            trail.record(run: run_id, type: "leak", target: target,
              addresses: found.transform_values { |v| format("0x%x", v) })
            write_manifest.call("running")
          end
        end

        # The repos have no exploit for the decided technique and the
        # binary is in hand: scaffold it (measured constants), trail it,
        # and the NEXT attempt discovers it. The operator still reviews
        # the file - the loop does not invent craft, it drafts it.
        scaffolded_now = false
        if !result[:executed] && binary && repo_dir && !scaffolded_techniques.include?(technique)
          require "augure-profiler" # lazy: the scaffold path loads metasm
          build = PayloadBuilder.build(binary: binary, facts: facts,
            technique: technique, out: File.join(repo_dir, "payload.bin"))
          dest = ExploitScaffold.scaffold(technique: technique, constants: build,
            repo_dir: repo_dir, author: "lictor run auto-scaffold")
          trail.record(run: run_id, type: "scaffold", technique: technique,
            offset: build[:offset], offset_source: build[:offset_source],
            ret: build[:ret_source], file: dest)
          scaffolded_now = true
          scaffolded_techniques << technique
          write_manifest.call("running")
        end
        attempt = {
          technique: technique, executed: result[:executed],
          success: result[:success], exploit: result[:exploit], handoff: result[:handoff],
          flag: result[:flag]
        }
        attempts << attempt
        # The outcome feeds the priors ONLY when something actually ran:
        # a handoff attempt (the safe default) never attempted anything,
        # and recording it as a failure systematically downgrades the
        # decided technique for every future decision.
        if result[:executed]
          trail.record(run: run_id, type: "outcome", technique: technique,
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
      write_manifest.call(status)
      {status: status, steps: attempts, leaks: leaks, run_id: run_id}
    end
  end
end
