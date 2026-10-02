# frozen_string_literal: true

require "augure"

module Lictor
  # Prior adaptation: the closed loop from the articles. Every recorded
  # outcome (success/failure) is fed back into the augure bandit priors,
  # so the next decision carries the engagement's own evidence. Same
  # seed, different facts, honest adaptation - and every step trailed.
  module Priors
    module_function

    def from_trail(trail, base: nil)
      base ||= Augure::Pipeline.default_priors
      priors = base.transform_values(&:dup)
      trail.events.each do |event|
        next unless event["type"] == "outcome"

        tech = event["technique"]
        priors[tech] ||= [1.0, 1.0]
        priors[tech][event["success"] ? 0 : 1] += 1
      end
      priors
    end

    def adapted?(trail)
      trail.events.any? { |event| event["type"] == "outcome" }
    end
  end
end
