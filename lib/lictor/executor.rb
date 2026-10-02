# frozen_string_literal: true

require "open3"

module Lictor
  # The execution layer. The interface is uniform; the implementations
  # differ in how much they dare. ManualExecutor (the default) executes
  # NOTHING - it hands off. RoninExecutor runs exploits from the
  # operator's ronin repos, discovered at runtime, never invented.
  class ExecutorError < StandardError; end

  module Executor
    module_function

    def resolve(kind)
      case kind
      when :manual, "manual" then ManualExecutor.new
      when :ronin, "ronin" then RoninExecutor.new
      else raise ExecutorError, "unknown executor #{kind.inspect} (manual|ronin)"
      end
    end
  end

  # The default: augure decided, lictor prints, a human runs.
  class ManualExecutor
    def execute(target:, technique:, recipe:, exploit_name: nil)
      {
        executed: false,
        success: nil,
        handoff: recipe[:console] || "manual handoff: #{technique} against #{target}"
      }
    end
  end

  # Runs an exploit from the operator's installed ronin repos. The
  # exploit NAME must come from discovery (ronin-exploits list) - a
  # fabricated name is an ExecutorError. The real run needs a lab; until
  # one exists this executor is wired and the lab phase plugs in.
  class RoninExecutor
    def initialize(runner: "ronin-exploits")
      @runner = runner
    end

    # The exploits available in the operator's repos, filtered to the
    # decided technique.
    def discover(technique)
      out, _err, status = Open3.capture3(@runner, "list")
      raise ExecutorError, "ronin-exploits list failed" unless status.success?

      out.lines.drop(1).filter_map do |line|
        name, tech = line.split
        name if tech && tech.strip == technique
      end
    end

    def execute(target:, technique:, recipe:, exploit_name:, consent_token: nil)
      matches = discover(technique)
      unless matches.include?(exploit_name)
        raise ExecutorError,
          "exploit #{exploit_name.inspect} not discovered in your repos (available: #{matches.join(", ")})"
      end

      out, _err, status = Open3.capture3(
        {@runner => @runner, "ROP_TARGET" => target, "ROP_TECHNIQUE" => technique},
        @runner, "run", exploit_name, "--target", target
      )
      {executed: true, success: status.success?, exploit: exploit_name, output: out}
    end
  end
end
