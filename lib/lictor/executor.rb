# frozen_string_literal: true

require "open3"
require "timeout"
require "timeout"
require "tmpdir"

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
    def execute(target:, technique:, recipe:, exploit_name: nil, payload: nil, timeout: nil)
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
    # A MINIMAL environment: under `bundle exec` any surviving bundler
    # hook (RUBYOPT's -rbundler/setup, a BUNDLE_* var, even the Gemfile
    # of the working directory) freezes the gem set to lictor's bundle -
    # and ronin-exploits is deliberately not in it, so the binstub dies
    # in Gem.activate_bin_path. HOME + the current ruby's bindir (where
    # `gem install` puts binstubs, plus mise shims when present) + the
    # system dirs: that is all the arsenal needs.
    CLEAN_ENV = {
      "HOME" => ENV["HOME"].to_s,
      "PATH" => [
        File.dirname(RbConfig.ruby),
        ENV["PATH"].to_s.split(":").find { |d| File.exist?(File.join(d, "mise")) },
        "/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"
      ].compact.join(":"),
      "LANG" => ENV["LANG"].to_s,
      "TERM" => ENV["TERM"].to_s
    }.freeze

    def initialize(runner: "ronin-exploits")
      @runner = runner
    end

    # The exploits available in the operator's repos, matched to the
    # decided technique by the naming convention
    # `<name>_<technique>_<nnn>` (ronin-exploits list shows names only).
    def discover(technique)
      out, _err, status = Open3.capture3(CLEAN_ENV, @runner, "list", unsetenv_others: true)
      raise ExecutorError, "ronin-exploits list failed" unless status.success?

      out.lines.filter_map do |line|
        name = line.strip
        name if name.include?(technique)
      end
    end

    def execute(target:, technique:, recipe:, exploit_name: nil, payload: nil, timeout: nil)
      exploit_name ||= discover(technique).first
      unless exploit_name
        return {executed: false, success: nil,
                note: "no #{technique} exploit in your repos (ronin-exploits list)"}
      end

      host, port = target.split(":", 2)
      args = ["run", exploit_name, "--param", "host=#{host || target}"]
      args += ["--param", "port=#{port}"] if port
      args += ["--param", "payload_file=#{File.expand_path(payload)}"] if payload
      # A neutral cwd: a Gemfile in the working directory pulls the
      # subprocess back into a bundle context where ronin-exploits
      # "is not included in the bundle".
      out, _err, status = nil
      Dir.chdir(Dir.tmpdir) do
        # unsetenv_others: true = the env -i semantics - Open3 would
        # otherwise MERGE CLEAN_ENV into the (bundler-contaminated)
        # parent environment.
        # the timeout kills the SERVER's wait, the child may linger: a
        # black-holed target must not hang the stdio loop forever
        out, _err, status = Timeout.timeout(timeout || 300) do
          Open3.capture3(CLEAN_ENV, @runner, *args, unsetenv_others: true)
        end
      rescue Timeout::Error, SignalException
        raise ExecutorError, "the runner timed out - a black-holed target hangs the loop"
      end
      {executed: true, success: status.success?, exploit: exploit_name, output: out}
    end
  end
end
