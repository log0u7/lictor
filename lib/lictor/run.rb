# frozen_string_literal: true

require "securerandom"
require_relative "gates"
require_relative "consent"
require_relative "handoff"
require_relative "priors"
require_relative "trail"

module Lictor
  # The closed loop, driven: decide (augure) -> execute the plan's next
  # step (executor, consent token required) -> outcome -> priors -> re-decide,
  # until a shell, or the budget runs out. Every step is trailed. The
  # handoff executor makes the whole loop safe by construction: it
  # "executes" by printing.
  module Run
    module_function

    def run(target:, facts:, trail:, consent_token:, executor: nil, max_attempts: 3,
      seed: nil, priors: nil, packs: nil)
      unless consent_token && Consent.valid?(trail, consent_token, target)
        raise Unauthorized, "execution requires a valid consent token for the exact target (lictor authorize <target>)"
      end

      executor ||= ManualExecutor.new
      attempts = []

      max_attempts.times do
        decision = Handoff.plan(facts: facts, seed: seed, priors: Priors.from_trail(trail), packs: packs)
        technique = decision[:selected]
        break if technique.nil?

        result = executor.execute(target: target, technique: technique,
          recipe: decision[:recipe])
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
