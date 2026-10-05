# frozen_string_literal: true

require "net/http"
require "uri"
require "fileutils"
require "open3"
require "timeout"
require "securerandom"

module Lictor
  # The nmap -> binary bridge. After the scan, WHERE does the binary come
  # from? Three honest answers: it is local (CTF/lab), it is
  # downloadable (http/ftp on the target), or the target is a pure
  # remote service with no retrievable ELF - in that case there is NO
  # profiling: the facts come from the scan (service/software_version)
  # and the service packs match them.
  class AcquisitionError < StandardError; end

  module Acquisition
    ELF_MAGIC = "\x7fELF"
    MAX_BYTES = 64 * 1024 * 1024

    module_function

    # source: "local:/path" or "http(s)://url". Returns {facts:, binary_path:}.
    def acquire(target, source:, trail:, out_dir: ".", profiler_cmd: nil)
      binary_path = fetch(source, out_dir: out_dir)
      unless File.open(binary_path, "rb") { |f| f.read(4) == ELF_MAGIC }
        raise AcquisitionError,
          "#{binary_path} is not an ELF - a pure remote service has no profiled " \
          "binary: its facts come from the scan (service facts) and service packs"
      end

      cmd = profiler_cmd || "augure-profile"
      out, err, status = Timeout.timeout(300) { Open3.capture3(cmd, binary_path) }
      unless status.success?
        raise AcquisitionError,
          "profiling failed: #{[out, err].map(&:strip).reject(&:empty?).join(" | ")}"
      end

      facts_path = File.join(out_dir, "target.facts")
      File.write(facts_path, out)
      trail.record(run: SecureRandom.uuid, type: "acquire", target: target,
        source: source, binary: binary_path)
      {facts: out, facts_path: facts_path, binary_path: binary_path}
    rescue Timeout::Error
      raise AcquisitionError, "profiling #{binary_path} timed out after 300s (hung metasm? check the binary)"
    end

    def fetch(source, out_dir:)
      case source
      when /\Alocal:(.+)/
        path = Regexp.last_match(1)
        raise AcquisitionError, "local source missing: #{path}" unless File.file?(path)

        dest = File.join(out_dir, File.basename(path))
        FileUtils.cp(path, dest) unless File.identical?(path, dest)
        dest
      when %r{\Ahttps?://}
        dest = File.join(out_dir, File.basename(URI(source).path))
        uri = URI(source)
        response = Net::HTTP.start(uri.host, uri.port, use_ssl: source.start_with?("https"),
          open_timeout: 10, read_timeout: 30) do |http|
          http.get(uri.request_uri)
        end
        raise AcquisitionError, "download failed: HTTP #{response.code}" unless response.code.to_i == 200

        body = response.body.to_s
        raise AcquisitionError, "download too large (max #{MAX_BYTES})" if body.bytesize > MAX_BYTES

        File.binwrite(dest, body)
        dest
      else
        raise AcquisitionError, "source must be local:/path or http(s)://url, got #{source.inspect}"
      end
    end
  end
end
