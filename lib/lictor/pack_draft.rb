# frozen_string_literal: true

require "fileutils"
require "yaml"
require "augure"
require "augure/pack_loader"

module Lictor
  # No technique applies and the crash carries facts: draft a PACK. The
  # draft is honest by construction - its rule records the observed
  # facts, its build layout carries the measured constants, and it goes
  # to the STAGING directory for the operator to review. The armor runs
  # on the draft before anything touches augure: a pack that would move
  # a frozen corpus verdict is refused, and it is never auto-installed.
  module PackDraft
    class DraftError < StandardError; end

    module_function

    # Returns the draft path, or nil when a built-in technique already
    # covers the observation (the draft says so instead of duplicating).
    def draft(facts:, measurements:, staging_dir:)
      decision = Augure::Pipeline.analyze(facts: facts, plan: false)
      unless decision[:applicable].empty?
        return nil # built-ins cover it: no pack needed, say so upstream
      end

      sink = measurements[:sink]
      raise DraftError, "no measured sink - the draft would be pure invention" unless sink

      name = "autodraft_#{sink}"
      layout = measurements[:offset] ? [["padding", "measured_offset"]] : []
      layout << ["qword", "win"] if facts.include?("win_symbol(")
      layout << ["shellcode", "sh"] if facts.include?("nx(\"false\")")

      yaml = {
        "technique" => name,
        "author" => "lictor auto-draft (operator review required)",
        "source" => "auto-draft from run #{measurements[:run_id]}",
        "rules" => [
          {
            "id" => "app_#{name}",
            "head" => ["applicable", name],
            "conditions" => [
              ["fact", "vuln", "sof"],
              ["fact", "sink", sink]
            ]
          }
        ],
        "kb" => [
          {
            "id" => "#{name}_001",
            "technique" => name,
            "description" => "Auto-drafted from the run's observations: the sink was #{sink}, " \
                             "the offset measured #{measurements[:offset]} (#{measurements[:offset_source]}). " \
                             "This draft records what was seen - the operator writes the craft.",
            "chain" => ["observed", "measured"],
            "unlocks" => [],
            "success_rate" => 0.3
          }
        ],
        "mcts" => {"requires" => [], "provides" => [], "terminal" => true, "success" => 0.3},
        "priors" => [5, 15],
        "build" => {"technique" => name, "arch" => "any", "layout" => layout}
      }
      require "yaml"
      text = YAML.dump(yaml)
      FileUtils.mkdir_p(staging_dir)
      dest = File.join(staging_dir, "#{name}.yml")
      File.write(dest, text)

      # the armor reads the draft: a refused draft stays on disk with
      # the refusal in the trail - the operator decides what to do
      status = begin
        Augure::PackLoader.load_dir(staging_dir)
        Augure::PackLoader.corpus_guard(Augure::PackLoader.load_dir(staging_dir))
        "valid"
      rescue Augure::PackError => e
        "refused: #{e.message[0, 80]}"
      end
      {path: dest, status: status, technique: name}
    end
  end
end
