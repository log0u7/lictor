# frozen_string_literal: true

require "open3"
require "timeout"

module Lictor
  # Bridge to the augure-profiler gem: binary in, facts out, through the
  # serialization boundary (the augure-profile subprocess). A facts file
  # passes through untouched - lictor accepts both.
  class ProfilerError < StandardError; end

  module Profiler
    ELF_MAGIC = "\x7fELF"
    DEFAULT_CMD = "augure-profile"

    module_function

    def elf?(path)
      File.open(path, "rb") { |f| f.read(4) == ELF_MAGIC }
    rescue
      false
    end

    def run(binary, cmd: DEFAULT_CMD, timeout: 300)
      stdout, stderr, status = Timeout.timeout(timeout) { Open3.capture3(cmd, binary) }
      unless status.success?
        hint = stderr.lines.first&.strip || "exit #{status.exitstatus}"
        raise ProfilerError,
          "profiling #{binary} failed: #{hint} (gem install augure-profiler?)"
      end
      stdout
    rescue Errno::ENOENT
      raise ProfilerError, "augure-profile not found (gem install augure-profiler)"
    rescue Timeout::Error
      raise ProfilerError, "profiling #{binary} timed out after #{timeout}s (hung gdb/metasm? check the binary)"
    end
  end
end
