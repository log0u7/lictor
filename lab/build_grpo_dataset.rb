#!/usr/bin/env ruby
# frozen_string_literal: true

# The GRPO dataset builder: one record per runnable lab target. The
# prompt carries the profiler's facts and asks for the source
# knowledge NO ELF can show; the completion is the suggest step the
# reward server counterfactually scores (1.0 the suggestion was the
# difference, 0.5 redundant, 0.0 nothing landed, -0.25 schema
# refused). The port/flag/facts ride the record as top-level columns:
# TRL passes them to the lab_loop reward as kwargs.
#
# The lab must be up (docker compose up -d --build); the binaries come
# off the same http server the demo acquires from.
#
#   bundle exec ruby lab/build_grpo_dataset.rb > /tmp/.../train.jsonl

require "json"
require "net/http"
require "open3"
require "tempfile"

# The demo's own port table (the server's PORT_BIN mirror).
TARGETS = {
  9999 => "ret2func", 9998 => "ret2plt", 9997 => "shellcode",
  9996 => "fmtstr", 9994 => "orw", 9993 => "callme", 9992 => "ret2csu"
}.freeze
SUBDIR = {"callme" => "emporium/callme/", "ret2csu" => "emporium/ret2csu/"}.freeze
HTTP_BASE = "http://127.0.0.1:8000/"

def facts_for(bin)
  Tempfile.open("grpo_ds") do |f|
    sub = SUBDIR.fetch(bin, "")
    body = Net::HTTP.get(URI.parse(HTTP_BASE + sub + bin))
    File.binwrite(f.path, body)
    out, _err = Open3.capture2(RbConfig.ruby,
      "-e", 'require "augure-profiler"; print AugureProfiler::Profiler.new(ARGV[0]).facts', f.path)
    out
  end
end

def prompt(bin, port, facts)
  <<~PROMPT
    The lab target #{bin} runs at 127.0.0.1:#{port}, its own flag is the oracle. The profiler already extracted the facts the ELF carries:

    #{facts}
    Propose ONLY the source-knowledge fact lines the ELF cannot show (a vuln class the static read missed, a heap class, a filter), one per line, in augure fact syntax such as vuln("sof"). Propose nothing the facts above already carry. Output fact lines only, no prose.
  PROMPT
end

TARGETS.each do |port, bin|
  facts = facts_for(bin)
  flag = File.read(File.expand_path("targets/#{bin}/flag.txt", __dir__)).strip
  record = {
    id: "lab-#{bin}-001",
    domain: "agentic",
    messages: [{role: "user", content: prompt(bin, port, facts)}],
    port: port,
    flag: flag,
    facts: facts,
    metadata: {pipeline: "lab", port: port, binary: bin}
  }
  puts JSON.generate(record)
end
