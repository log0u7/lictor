# frozen_string_literal: true

require "augure"

module Lictor
  # The authorization gates. Nothing in Lictor runs without an allowlist
  # naming hosts the operator is explicitly authorized to touch, and no
  # automated execution happens without the per-run consent flag.
  module Gates
    module_function

    def allowlist(path)
      entries = File.readlines(path).map(&:strip).reject { |l| l.empty? || l.start_with?("#") }
      wildcards = entries.select { |l| l.include?("*") || l.include?("?") }
      raise Unauthorized, "wildcards are not allowed in the target allowlist: #{wildcards.join(", ")}" if wildcards.any?

      entries
    end

    def require_authorized!(consent_flag, allowlist_path, target: nil)
      unless consent_flag
        raise Unauthorized, "automated execution requires --i-am-authorized on this run " \
                            "(handoff mode prints recipes instead)"
      end
      raise Unauthorized, "a target allowlist file is required" unless allowlist_path

      entries = allowlist(allowlist_path)
      raise Unauthorized, "an explicit --target is required for an authorized run" if target.nil?
      unless entries.include?(target)
        raise Unauthorized, "#{target} is not in the allowlist (#{allowlist_path})"
      end

      true
    end
  end
end
