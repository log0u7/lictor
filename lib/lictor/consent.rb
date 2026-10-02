# frozen_string_literal: true

require "securerandom"
require "time"

module Lictor
  # Execution consent: an interactive, typed confirmation recorded in the
  # trail as a short-lived token. An agent (or a reflexive operator)
  # cannot mint one - it exists only because a human typed the target
  # name at a terminal. One token, one target, one expiration.
  module Consent
    module_function

    def issue(trail, target, confirm_input:, ttl_seconds: 900)
      confirmed = confirm_input.to_s.strip
      unless confirmed == target
        raise Unauthorized, "confirmation mismatch - type the target name exactly to authorize execution"
      end

      token = SecureRandom.uuid
      trail.record(
        run: SecureRandom.uuid, type: "consent", target: target, token: token,
        expires_at: (Time.now.utc + ttl_seconds).iso8601
      )
      token
    end

    def valid?(trail, token, target)
      trail.events.reverse_each do |event|
        next unless event["type"] == "consent"
        next unless event["token"] == token && event["target"] == target

        expires = Time.iso8601(event["expires_at"])
        return expires > Time.now.utc
      rescue ArgumentError
        next
      end
      false
    end
  end
end
