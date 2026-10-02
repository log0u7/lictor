# frozen_string_literal: true

module Lictor
  # The authorization model. There is no consent flag: a flag can be typed
  # by reflex, by script, or by anyone with shell access - it proves
  # nothing. The controls are real artifacts:
  #
  #   1. the allowlist file: explicit host[:port] entries, written, read
  #      and versioned by the operator. THE scope document.
  #   2. the trail: every action recorded, attributable.
  #
  # Anything beyond scope is Unauthorized. When a future command executes
  # exploits, its confirmation is interactive (show the recipe, type the
  # target to confirm) - friction with information, not flag theater.
  module Gates
    module_function

    def allowlist(path)
      raise Unauthorized, "an allowlist file is required" unless path

      entries = File.readlines(path).map(&:strip).reject { |l| l.empty? || l.start_with?("#") }
      wildcards = entries.select { |l| l.include?("*") || l.include?("?") }
      if wildcards.any?
        raise Unauthorized, "wildcards are not allowed in the target allowlist: #{wildcards.join(", ")}"
      end

      entries
    end

    def require_in_scope!(allowlist_path, target)
      entries = allowlist(allowlist_path)
      # An entry may name host:port; that authorizes the host itself too
      # (colon-delimited prefix match, so 192.168.56.1 cannot pass for
      # 192.168.56.10).
      in_scope = entries.include?(target) ||
        entries.any? { |e| e.start_with?("#{target}:") }
      return true if in_scope

      raise Unauthorized, "#{target} is not in the allowlist (#{allowlist_path})"
    end
  end
end
