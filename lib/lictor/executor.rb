# frozen_string_literal: true

require "open3"
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
    def execute(target:, technique:, recipe:, exploit_name: nil, payload: nil, timeout: nil, flag_regex: nil,
      params: nil)
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

    # The watchdog caps. SOFT: a runner producing NO output for this
    # many seconds is hung (the exact MR6-bench hang: a menu reader
    # waiting on a banner the target never prints) - kill it. An
    # exploit that keeps producing output lives and gets the hard cap
    # instead. HARD: the wall-clock cap kills a chatty runner that
    # never finishes. Both caps kill the whole PROCESS GROUP: the
    # orphan leak the old capture3+Timeout path measured (three 1-3h
    # old ruby workers abandoned mid-hang) cannot happen.
    SOFT_TIMEOUT = 30
    HARD_TIMEOUT = 120

    def initialize(runner: "ronin-exploits", soft_timeout: SOFT_TIMEOUT)
      @runner = runner
      @soft_timeout = soft_timeout
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

    def execute(target:, technique:, recipe:, exploit_name: nil, payload: nil, timeout: nil, flag_regex: nil,
      params: nil)
      exploit_name ||= discover(technique).first
      unless exploit_name
        return {executed: false, success: nil,
                note: "no #{technique} exploit in your repos (ronin-exploits list)"}
      end

      host, port = target.split(":", 2)
      args = ["run", exploit_name, "--param", "host=#{host || target}"]
      args += ["--param", "port=#{port}"] if port
      args += ["--param", "payload_file=#{File.expand_path(payload)}"] if payload
      # The measured constants an exploit declares beyond host/port/payload:
      # the run layer derives them from the fact store (win_addr from the
      # measured win symbol, for the uaf class). An exploit that declares
      # no such param refuses it - ronin errors loudly, the trail shows it.
      args += params.flat_map { |k, v| ["--param", "#{k}=#{v}"] } if params
      # A neutral cwd: a Gemfile in the working directory pulls the
      # subprocess back into a bundle context where ronin-exploits
      # "is not included in the bundle".
      out, timed_out, status = nil
      Dir.chdir(Dir.tmpdir) do
        out, timed_out, status = run_with_watchdog(args, hard_timeout: timeout || HARD_TIMEOUT)
      end
      # A timeout is an outcome, not a crash: the trail shows the
      # attempt as "hung and killed" (timeout: true), the budget counts
      # it, the run moves on to the next technique.
      if timed_out
        return {executed: true, success: false, exploit: exploit_name,
                output: out, timeout: true}
      end
      # Success semantics: the flag in the OUTPUT is the truth the
      # operator cares about; the exit code lies both ways (a polite
      # exploit exits 0 on failure, a caught-cleanup exploit exits
      # non-zero after landing the flag). Without a flag regex the exit
      # code stays the oracle - the honest, weaker fallback.
      if flag_regex
        flag = out[/#{flag_regex}/]
        {executed: true, success: !flag.nil?, exploit: exploit_name, output: out, flag: flag}
      else
        {executed: true, success: status.success?, exploit: exploit_name, output: out}
      end
    end

    private

    # The watchdog runner: popen2e with the child in its OWN process
    # group (pgroup: true), so the kill below takes every descendant -
    # the capture3+Timeout path left the child alive (an orphan worker
    # kept hanging for hours mid-bench). Two caps:
    # - HARD: the wall-clock cap. A chatty-but-never-finishing runner
    #   dies even though it keeps producing output.
    # - SOFT: no NEW output for @soft_timeout seconds = hung. A menu
    #   reader waiting on a banner the target never prints produces
    #   nothing and dies here, minutes instead of hours.
    # Completion is the runner process EXITING (never the pipe EOF -
    # a grandchild can keep the pipe open). A timeout returns
    # [output, true, nil]; a normal exit returns [output, false, status].
    def run_with_watchdog(args, hard_timeout:)
      out = +""
      timed_out = false
      status = nil
      Open3.popen2e(CLEAN_ENV, @runner, *args, unsetenv_others: true, pgroup: true) do |stdin, pipe, waiter|
        stdin.close # the exploits read nothing from stdin (capture3 semantics)
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        last_output = started
        wait_thr = Thread.new { waiter.value }
        loop do
          now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          if now - started >= hard_timeout
            timed_out = true
            kill_group(waiter.pid)
            wait_thr.join(2) # the group kill lands: reap, no zombie
            break
          end
          if pipe
            if IO.select([pipe], nil, nil, 0.5)
              begin
                out << pipe.readpartial(4096)
                last_output = now
              rescue EOFError
                # the runner closed its streams - it exited (or a
                # grandchild still holds the pipe; the wait_thr below
                # is the truth). Stop reading, keep the caps running.
                pipe = nil
              end
            elsif now - last_output >= @soft_timeout
              timed_out = true
              kill_group(waiter.pid)
              wait_thr.join(2) # the group kill lands: reap, no zombie
              break
            end
          else
            sleep 0.1 # EOF: no more output can arrive; let the exit land
          end
          if wait_thr.join(0)
            status = wait_thr.value
            break
          end
        end
        unless timed_out
          wait_thr.join # reap the normal exit
          status = wait_thr.value
          if pipe # drain the tail the runner wrote just before exiting
            while IO.select([pipe], nil, nil, 1)
              begin
                out << pipe.readpartial(4096)
              rescue EOFError
                break
              end
            end
          end
        end
      end
      [out, timed_out, status]
    end

    # Kill the runner's whole process group (pgroup: true made the
    # child its own group leader): a plain PID kill leaves the ronin
    # children orphaned - the exact leak the bench measured.
    def kill_group(pid)
      Process.kill("-KILL", Process.getpgid(pid))
    rescue Errno::ESRCH, Errno::EPERM
      nil
    end
  end
end
