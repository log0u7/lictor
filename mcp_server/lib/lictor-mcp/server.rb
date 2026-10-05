# frozen_string_literal: true

require "mcp"
require "lictor"

module LictorMcp
  # The MCP surface of the orchestrator: the LLM harness's hands.
  # Every tool runs server-side - the pack armor, the corpus guard,
  # the trail (0600). The agent proposes; augure disposes; lictor
  # executes; the trail records everything.
  module ToolHelpers
    module_function

    def respond(payload)
      ::MCP::Tool::Response.new([{type: "text", text: ::JSON.generate(payload)}])
    end

    def error(message)
      ::MCP::Tool::Response.new([{type: "text", text: ::JSON.generate(error: message)}])
    end

    def trail
      ::Lictor::Trail.new(::Lictor::Config.load[:trail] || "lictor-mcp-trail.jsonl")
    end
  end

  class Server
    include ToolHelpers

    TOOLS = [
      ScanTarget = Class.new(::MCP::Tool) do
        description "Run nmap against a target and return the target inventory."
        input_schema(properties: {
          host: {type: "string"}
        }, required: %w[host])

        class << self
          include ::LictorMcp::ToolHelpers

          def call(host:, server_context: nil)
            targets = nil
            Dir.mktmpdir do |d|
              targets = ::Lictor::Scanner.run(host, out: File.join(d, "s.xml"))
            end
            trail.record(run: SecureRandom.uuid, type: "scan", target: host)
            respond(targets: targets, candidates: targets.map { |t| "#{t[:host]}:#{t[:port]}" })
          rescue ::Lictor::ScanError => e
            error(e.message)
          end
        end
      end,

      PlanTechnique = Class.new(::MCP::Tool) do
        description "Decide on facts (or a binary - profiled automatically) and return the " \
                    "auditable decision with rule provenance. Augure disposes: the agent " \
                    "augure decides - you cannot pick an unverified technique."
        input_schema(properties: {
          target: {type: "string", description: "binary path or .facts path"}
        }, required: %w[target])

        class << self
          include ::LictorMcp::ToolHelpers

          def call(target:, server_context: nil)
            facts = ::Lictor::Profiler.elf?(target) ? ::Lictor::Profiler.run(target) : File.read(target)
            packs = ::Lictor::TechniquePacks.load(::Lictor::Config.load[:packs] || "packs")
            decision = ::Lictor::Handoff.plan(facts: facts, priors: ::Lictor::Priors.from_trail(trail), packs: packs)
            trail.record(run: SecureRandom.uuid, type: "plan", selected: decision[:selected],
              applicable: decision[:applicable])
            respond(decision)
          rescue ::Augure::MalformedFact, ::Augure::UnknownPredicate, ::Lictor::ProfilerError => e
            error(e.message)
          end
        end
      end,

      ExecuteTechnique = Class.new(::MCP::Tool) do
        description "Execute the decided technique against the target. " \
                    "The executor discovers exploits from the operator's repos; it never " \
                    "invents one. The trail records what actually executed."
        input_schema(properties: {
          target: {type: "string"}, technique: {type: "string"},
          exploit_name: {type: "string", description: "from your repos (ronin-exploits list)"},
          payload_file: {type: "string", description: "a pre-built payload from lictor build"}
        }, required: %w[target technique exploit_name])

        class << self
          include ::LictorMcp::ToolHelpers

          def call(target:, technique:, exploit_name:, payload_file: nil, server_context: nil)
            executor = ::Lictor::Executor.resolve(:ronin)
            result = executor.execute(target: target, technique: technique, recipe: {console: ""},
              exploit_name: exploit_name, payload: payload_file)
            trail.record(run: SecureRandom.uuid, type: "outcome", technique: technique,
              success: result[:success] == true, executed: result[:executed],
              target: target)
            respond(result)
          rescue ::Lictor::ExecutorError => e
            error(e.message)
          end
        end
      end,

      ValidatePack = Class.new(::MCP::Tool) do
        description "Validate a technique pack through the full armor (schema, stratification, " \
                    "corpus guard). Installing needs the operator's " \
                    "interactive confirmation - validation alone is safe."
        input_schema(properties: {pack_path: {type: "string"}}, required: %w[pack_path])

        class << self
          include ::LictorMcp::ToolHelpers

          def call(pack_path:, server_context: nil)
            pack = ::Augure::PackLoader.load_file(pack_path)
            ::Augure::PackLoader.corpus_guard([pack])
            respond(valid: true, technique: pack.technique, author: pack.author, source: pack.source)
          rescue ::Augure::PackError => e
            error("pack refused: #{e.message}")
          end
        end
      end,
      BuildPayload = Class.new(::MCP::Tool) do
        description "Assemble the payload for the decided technique: the offset is " \
                    "MEASURED (static frame read, the debugger as fallback), the return " \
                    "address comes from the facts, the shellcode is assembly source. " \
                    "Writes a payload file and trails the build."
        input_schema(properties: {
          binary: {type: "string", description: "the acquired local ELF copy"},
          facts_path: {type: "string", description: "the .facts file"},
          technique: {type: "string", description: "defaults to the plan's selection"},
          payload_file: {type: "string", description: "custom shellcode/payload bytes"}
        }, required: %w[binary facts_path])

        class << self
          include ::LictorMcp::ToolHelpers

          def call(binary:, facts_path:, technique: nil, payload_file: nil, server_context: nil)
            facts = ::File.read(facts_path)
            packs = ::Lictor::TechniquePacks.load(::Lictor::Config.load[:packs] || "packs")
            technique ||= ::Lictor::Handoff.plan(facts: facts, packs: packs)[:selected]
            raise ::Lictor::PayloadBuilder::BuildError, "no technique selected - plan decided nothing" unless technique

            result = ::Lictor::PayloadBuilder.build(binary: binary, facts: facts,
              technique: technique, out: ::File.join(::Dir.tmpdir, "lictor-payload-#{::Process.pid}.bin"),
              payload_file: payload_file)
            trail.record(run: ::SecureRandom.uuid, type: "build", technique: technique,
              offset: result[:offset], offset_source: result[:offset_source],
              ret: result[:ret_source], size: result[:size], out: result[:path])
            respond(result)
          rescue ::Lictor::PayloadBuilder::BuildError, ::Augure::MalformedFact, ::Augure::UnknownPredicate => e
            error(e.message)
          end
        end
      end,

      ScaffoldExploit = Class.new(::MCP::Tool) do
        description "Draft a ronin exploit for the decided technique, carrying the measured " \
                    "constants: the file lands in the staging directory and the OPERATOR " \
                    "reviews and commits it. The exploit NAME follows the discovery convention."
        input_schema(properties: {
          binary: {type: "string"},
          facts_path: {type: "string"},
          technique: {type: "string"},
          staging_dir: {type: "string", description: "where the draft lands (operator-reviewed)"}
        }, required: %w[binary facts_path technique staging_dir])

        class << self
          include ::LictorMcp::ToolHelpers

          def call(binary:, facts_path:, technique:, staging_dir:, server_context: nil)
            # The scaffold touches no target: the staging directory is
            # where the draft lands, the operator reviews, the trail
            # records.
            facts = ::File.read(facts_path)
            result = ::Lictor::PayloadBuilder.build(binary: binary, facts: facts,
              technique: technique, out: ::File.join(::Dir.tmpdir, "lictor-payload-#{::Process.pid}.bin"))
            dest = ::Lictor::ExploitScaffold.scaffold(technique: technique, constants: result,
              repo_dir: staging_dir, author: "lictor-mcp scaffold (operator review required)")
            trail.record(run: ::SecureRandom.uuid, type: "scaffold", technique: technique,
              offset: result[:offset], ret: result[:ret_source], file: dest)
            respond(scaffolded: dest, review: "the operator reads and commits this file")
          rescue ::Lictor::PayloadBuilder::BuildError, ::Lictor::ExploitScaffold::ScaffoldError,
            ::Augure::MalformedFact, ::Augure::UnknownPredicate => e
            error(e.message)
          end
        end
      end,

      SuggestFacts = Class.new(::MCP::Tool) do
        description "Submit hypothesis facts on top of an existing fact base; the closed " \
                    "schema is the whitelist (no applicable() exists to forge), augure " \
                    "re-decides on the merged base, and the delta comes back. The trail " \
                    "records who proposed what and what changed."
        input_schema(properties: {
          facts_path: {type: "string", description: "path to the base .facts file"},
          suggested_facts: {type: "string", description: "hypothesis facts, one predicate(\"atom\"). per line"}
        }, required: %w[facts_path suggested_facts])

        class << self
          include ::LictorMcp::ToolHelpers

          def call(facts_path:, suggested_facts:, server_context: nil)
            result = ::Lictor::Suggestion.apply(base_facts: File.read(facts_path),
              suggested: suggested_facts, trail: trail, target: facts_path)
            respond(target: facts_path, delta: {
              added: result[:added],
              applicable_before: result[:applicable_before],
              applicable_after: result[:applicable_after],
              selected_before: result[:selected_before],
              selected_after: result[:selected_after]
            })
          rescue ::Augure::MalformedFact => e
            # the parse error embeds the offending line: a file named by
            # the caller must not leak its content through the error
            error(e.message.sub(/line \d+: malformed fact .*/, "line ?"))
          rescue ::Augure::UnknownPredicate => e
            error(e.message)
          end
        end
      end
    ].freeze

    def self.build
      ::MCP::Server.new(name: "lictor-mcp", version: ::LictorMcp::VERSION, tools: TOOLS).tap do |server|
        server.instructions = "lictor orchestrates the augure decision layer. The operator is " \
                              "the authorization; the trail is the record."
      end
    end
  end
end
