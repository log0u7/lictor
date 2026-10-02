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
  # fabricated name is an ExecutorError. The ronin subprocess runs
  # OUTSIDE the caller's bundle (RUBYOPT stripped): the operator
  # installs ronin-exploits globally (gem install, the lab setup does
  # it) - the executor does not drag the arsenal into its own bundle.
  class RoninExecutor
    CLEAN_ENV = {"RUBYOPT" => nil, "BUNDLE_GEMFILE" => nil, "BUNDLE_BIN_PATH" => nil}.freeze

    def initialize(runner: "ronin-exploits")
      @runner = runner
    end

    # The exploits available in the operator's repos, matched to the
    # decided technique by the naming convention
    # `<name>_<technique>_<nnn>` (ronin-exploits list shows names only).
    def discover(technique)
      out, _err, status = Open3.capture3(CLEAN_ENV, @runner, "list")
      raise ExecutorError, "ronin-exploits list failed" unless status.success?

      out.lines.filter_map do |line|
        name = line.strip
        name if name.include?(technique)
      end
    end

    def execute(target:, technique:, recipe:, exploit_name: nil, consent_token: nil)
      exploit_name ||= discover(technique).first
      unless exploit_name
        return {executed: false, success: nil,
                note: "no #{technique} exploit in your repos (ronin-exploits list)"}
      end

      host, port = target.split(":", 2)
      args = ["run", exploit_name, "--param", "host=#{host || target}"]
      args += ["--param", "port=#{port}"] if port
      out, _err, status = Open3.capture3(CLEAN_ENV, @runner, *args)
      {executed: true, success: status.success?, exploit: exploit_name, output: out}
    end
  end
end
