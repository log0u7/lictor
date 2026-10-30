#!/usr/bin/env ruby
# frozen_string_literal: true

# The GRPO reward server: the model's completion IS the suggest step.
# A request carries the target's port, the target's own flag, the
# profiler's facts and the completion (the proposed source-knowledge
# fact lines). The server runs the counterfactual: the SAME pipeline
# (plan -> build -> run) on the raw facts and on the suggest-enriched
# facts. The reward: 1.0 when the treated side lands the target's own
# flag and the baseline does not (the suggestion was the difference),
# 0.5 when the pipeline lands either way (redundant knowledge), 0.0
# when nothing lands, -0.25 when the completion does not parse as
# facts.
#
# Run from the lictor checkout (the bundler context brings augure and
# the profiler) with the lab up:
#
#   bundle exec ruby lab/grpo_reward_server.rb
#
# The trainer reaches it through an ssh reverse tunnel (run
# `ssh -R 9090:127.0.0.1:9090 <gpu-host>` from this box), so the
# training host calls http://127.0.0.1:9090/reward and lands on this
# box's lab.

require "json"
require "net/http"
require "open3"
require "socket"
require "fileutils"
require "tmpdir"
require "timeout"

module GrpoReward
  FULL_REWARD = 1.0
  ZERO_REWARD = 0.0
  REDUNDANT_REWARD = 0.5
  MALFORMED_REWARD = -0.25
  PLAN_TIMEOUT = 120
  BUILD_TIMEOUT = 180
  RUN_TIMEOUT = 300
  PORT = ENV.fetch("GRPO_REWARD_PORT", "9090").to_i

  module_function

  # The lictor CLI runs from the checkout this file ships in.
  def lictor
    File.expand_path("../bin/lictor", __dir__)
  end

  # The completion may carry anything the model produced: keep the
  # fact-shaped lines. A completion with NO parseable line pays; a few
  # stray lines ride along, the suggest schema does the rejecting.
  def fact_lines(completion)
    lines = completion.to_s.lines.map(&:strip).reject(&:empty?)
    keep = lines.select { |l| l.match?(/\A[a-z_0-9]+\(.*\)\.\z/m) }
    keep.empty? ? nil : keep
  end

  # The lab's port -> [binary name, http subpath] map (the demo's own
  # table): the pipeline needs the ELF to measure against.
  PORT_BIN = {
    "9999" => ["ret2func", ""], "9998" => ["ret2plt", ""],
    "9997" => ["shellcode", ""], "9996" => ["fmtstr", ""],
    "9994" => ["orw", ""], "9993" => ["callme", "emporium/callme/"],
    "9992" => ["ret2csu", "emporium/ret2csu/"]
  }.freeze
  HTTP_BASE = "http://127.0.0.1:8000/"

  # One pipeline pass: plan -> build walk (the demo's rule: the first
  # BUILDABLE rank wins) -> run. Returns [success, last_status]. The
  # exit code lies both ways (a budget-exhausted run exits 0): the
  # run's own status line is the honest oracle.
  def pipeline(work, bin:, port:, flag_regex:)
    plan = Timeout.timeout(PLAN_TIMEOUT) do
      Open3.capture3(lictor, "plan", "target.facts", "-s", "7", chdir: work)
    end
    ranked = plan[0][/^ranking:[ \t]+(.*)$/, 1]
    ranked = ranked.split(">").map(&:strip).reject(&:empty?) if ranked
    return [false, "no applicable technique"] if !ranked || ranked.empty?

    # the debugger runs the binary IN the workdir: the companion
    # library (callme, ret2csu) must ride beside it (the loader
    # resolves it there)
    lib = File.join(work, "lib#{File.basename(bin)}.so")
    env = File.file?(lib) ? {"LD_LIBRARY_PATH" => work} : {}
    built = nil
    ranked.each do |technique|
      build = Timeout.timeout(BUILD_TIMEOUT) do
        Open3.capture3(env, lictor, "build", bin, "--facts", "target.facts",
          "--technique", technique, "-o", "payload.bin", "-s", "7", chdir: work)
      end
      if build[2].success?
        built = technique
        break
      end
    end

    args = ["run", "127.0.0.1:#{port}", "--facts", "target.facts", "--executor", "ronin",
      "--max-attempts", "2", "-s", "7", "--flag-regex", flag_regex]
    # the built payload pins the pipeline: the run's own bandit draw
    # could pick a technique whose layout differs from the payload the
    # build just produced. A technique with no layout (the exploits
    # that measure themselves) runs unpinned, no payload.
    args += ["--technique", built, "--payload", "payload.bin"] if built
    run = Timeout.timeout(RUN_TIMEOUT) do
      Open3.capture3(lictor, *args, chdir: work)
    end
    File.write(File.join(work, "last_run.out"), run[0])
    [run[0].match?(/^status:\s+success\b/), run[0].scan(/^status:\s+\S+/).last.to_s.strip]
  rescue Timeout::Error
    [false, "timeout"]
  end

  # The counterfactual is the gradient. Both sides run the SAME
  # pipeline (plan -> build -> run), the baseline on the raw facts,
  # the treated on the suggest-enriched facts.
  def run_loop(port:, flag:, facts:, completion:)
    lines = fact_lines(completion)
    flag_regex = Regexp.escape(flag)
    entry = PORT_BIN[port.to_s] or return {reward: ZERO_REWARD, detail: "unknown port #{port}"}
    bin, subpath = entry

    work = ENV["GRPO_DEBUG_WORK"] || Dir.mktmpdir("grpo_reward")
    begin
      FileUtils.rm_rf(work) if ENV["GRPO_DEBUG_WORK"]
      FileUtils.mkdir_p(work)
      File.write(File.join(work, "lictor.yml"),
        "trail: trail.jsonl\npacks: #{File.expand_path("augure/packs", __dir__)}\n")
      binpath = File.join(work, bin)
      File.binwrite(binpath, Net::HTTP.get(URI.parse(HTTP_BASE + subpath + bin)))
      %w[callme ret2csu].include?(bin) &&
        File.binwrite(File.join(work, "lib#{bin}.so"),
          Net::HTTP.get(URI.parse(HTTP_BASE + subpath + "lib#{bin}.so")))
      File.write(File.join(work, "target.facts"), facts.to_s)
      baseline, base_out = pipeline(work, bin: binpath, port: port, flag_regex: flag_regex)
      if lines.nil?
        return {reward: baseline ? REDUNDANT_REWARD : ZERO_REWARD,
                detail: "nothing to add (#{base_out})"}
      end

      _out, err, status = Open3.capture3(lictor, "suggest", "target.facts", lines.join("\n"),
        "-o", "target.facts", chdir: work)
      return {reward: MALFORMED_REWARD, detail: "suggest refused: #{err.strip[0, 200]}"} unless status.success?

      treated, treated_out = pipeline(work, bin: binpath, port: port, flag_regex: flag_regex)
      reward, detail = if treated && !baseline
        [FULL_REWARD, "the suggestion was the difference"]
      elsif treated
        [REDUNDANT_REWARD, "the pipeline lands without the suggestion"]
      else
        [ZERO_REWARD, "the suggestion did not make it fall (" +
          treated_out.lines.map(&:strip).reject(&:empty?).last(2).join(" | ") + ")"]
      end
      {reward: reward, detail: detail}
    ensure
      FileUtils.rm_rf(work) unless ENV["GRPO_DEBUG_WORK"]
    end
  rescue => e
    {reward: ZERO_REWARD, detail: "#{e.class}: #{e.message[0, 200]}"}
  end

  def handle(payload)
    JSON.generate(run_loop(port: payload.fetch("port"), flag: payload.fetch("flag"),
      facts: payload.fetch("facts"), completion: payload.fetch("completion")))
  end

  def reply(sock, body)
    sock.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" \
               "Content-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}")
    sock.close
  rescue
    nil
  end

  # A client may keep the connection open (no EOF): the request is read
  # by contract, the header block terminated by \r\n\r\n, then exactly
  # Content-Length bytes.
  def read_request(sock)
    header = +""
    until header.end_with?("\r\n\r\n")
      c = sock.read(1)
      return nil unless c

      header << c
    end
    length = header[/Content-Length:\s*(\d+)/i, 1].to_i
    body = +""
    body << sock.read(length - body.bytesize) while body.bytesize < length
    JSON.parse(body)
  end

  def serve
    # the measurement sweeps run the target until it segfaults (the
    # offset IS the crash): without this the every-crash coredump
    # floods apport and the box drowns (measured: load 120 on 8 cores)
    begin
      Process.setrlimit(Process::RLIMIT_CORE, 0)
    rescue
      nil
    end
    server = TCPServer.new("127.0.0.1", PORT)
    puts "grpo reward server on 127.0.0.1:#{PORT}"
    loop do
      Thread.start(server.accept) do |sock|
        payload = read_request(sock)
        reply(sock, payload ? handle(payload) : JSON.generate({reward: ZERO_REWARD, detail: "unparseable request"}))
      rescue => e
        reply(sock, JSON.generate({reward: ZERO_REWARD, detail: "#{e.class}: #{e.message[0, 200]}"}))
      ensure
        begin
          sock.close
        rescue
          nil
        end
      end
    end
  end
end

GrpoReward.serve if $PROGRAM_NAME == __FILE__
