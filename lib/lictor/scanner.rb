# frozen_string_literal: true

require "open3"
require_relative "recon"

module Lictor
  # Active scanning: nmap as a subprocess against a target,
  # consented target. The scan is an ACTION - same gates as everything
  # else, and it is trailed. Recon (XML parsing) stays passive.
  class ScanError < StandardError; end

  module Scanner
    NMAP_ARGS = ["-sV", "-Pn"].freeze

    module_function

    def run(target, out:, nmap_cmd: "nmap", extra_args: [])
      require "timeout"
      _, stderr, status = Timeout.timeout(600) do
        Open3.capture3(nmap_cmd, *NMAP_ARGS, *extra_args, "-oX", out, target)
      end
      unless status.success?
        reason = stderr.lines.first&.strip || "exit #{status.exitstatus}"
        raise ScanError, "nmap failed on #{target}: #{reason} (is nmap installed?)"
      end
      Recon.from_nmap_xml(out)
    rescue Errno::ENOENT
      raise ScanError, "nmap binary not found: #{nmap_cmd} (is nmap installed?)"
    end
  end
end
