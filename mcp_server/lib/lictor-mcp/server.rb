# frozen_string_literal: true

require "mcp"
require "lictor"

module LictorMcp
  # The gated MCP surface of the orchestrator: the LLM harness's hands.
  # EVERY tool validates server-side - the allowlist, the consent tokens,
  # the corpus guard - and trails everything. The agent proposes; augure
  # disposes; lictor executes; nothing escapes the gates.
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
        description "Run nmap against an allowlisted host and return the target inventory. " \
                    "Server-side gates: the host must be in the allowlist file."
        input_schema(properties: {
          host: {type: "string"}, allowlist: {type: "string", description: "Path to targets.yml"}
        }, required: %w[host allowlist])

        class << self
          include ::LictorMcp::ToolHelpers

          def call(host:, allowlist:, server_context: nil)
            ::Lictor::Gates.require_in_scope!(allowlist, host)
            targets = nil
            Dir.mktmpdir do |d|
              targets = ::Lictor::Scanner.run(host, out: File.join(d, "s.xml"))
            end
            trail.record(run: SecureRandom.uuid, type: "scan", target: host)
            respond(targets: targets, candidates: targets.map { |t| "#{t[:host]}:#{t[:port]}" })
          rescue ::Lictor::Unauthorized => e
            error("UNAUTHORIZED: #{e.message}")
          rescue ::Lictor::ScanError => e
            error(e.message)
          end
        end
      end,

      PlanTechnique = Class.new(::MCP::Tool) do
        description "Decide on facts (or a binary - profiled automatically) and return the " \
                    "auditable decision with rule provenance. Augure disposes: the agent " \
                    "cannot pick an unverified technique. Requires an allowlist."
        input_schema(properties: {
          target: {type: "string", description: "binary path or .facts path"},
          allowlist: {type: "string"}
        }, required: %w[target allowlist])

        class << self
          include ::LictorMcp::ToolHelpers

          def call(target:, allowlist:, server_context: nil)
            ::Lictor::Gates.allowlist(allowlist)
            facts = ::Lictor::Profiler.elf?(target) ? ::Lictor::Profiler.run(target) : File.read(target)
            packs = ::Lictor::TechniquePacks.load(::Lictor::Config.load[:packs] || "packs")
            decision = ::Lictor::Handoff.plan(facts: facts, priors: ::Lictor::Priors.from_trail(trail), packs: packs)
            trail.record(run: SecureRandom.uuid, type: "plan", selected: decision[:selected],
              applicable: decision[:applicable])
            respond(decision)
          rescue ::Lictor::Unauthorized => e
            error("UNAUTHORIZED: #{e.message}")
          rescue ::Augure::MalformedFact, ::Augure::UnknownPredicate, ::Lictor::ProfilerError => e
            error(e.message)
          end
        end
      end,

      ExecuteTechnique = Class.new(::MCP::Tool) do
        description "Execute the decided technique against the target - REQUIRES a consent " \
                    "token (lictor authorize <target>, typed by the human, short-lived). " \
                    "The executor discovers exploits from the operator's repos; it never " \
                    "invents one."
        input_schema(properties: {
          target: {type: "string"}, technique: {type: "string"},
          exploit_name: {type: "string", description: "from your repos (ronin-exploits list)"},
          consent_token: {type: "string"}, allowlist: {type: "string"},
          payload_file: {type: "string", description: "a pre-built payload from lictor build"}
        }, required: %w[target technique exploit_name consent_token allowlist])

        class << self
          include ::LictorMcp::ToolHelpers

          def call(target:, technique:, exploit_name:, consent_token:, allowlist:, payload_file: nil, server_context: nil)
            ::Lictor::Gates.require_in_scope!(allowlist, target)
            unless ::Lictor::Consent.valid?(trail, consent_token, target)
              return error("consent token invalid, expired, or for another target (lictor authorize <target>)")
            end

            executor = ::Lictor::Executor.resolve(:ronin)
            result = executor.execute(target: target, technique: technique, recipe: {console: ""},
              exploit_name: exploit_name, payload: payload_file)
            trail.record(run: SecureRandom.uuid, type: "outcome", technique: technique,
              success: result[:success] == true, executed: true, target: target)
            respond(result)
          rescue ::Lictor::Unauthorized => e
            error("UNAUTHORIZED: #{e.message}")
          rescue ::Lictor::ExecutorError => e
            error(e.message)
          end
        end
      end,

      ValidatePack = Class.new(::MCP::Tool) do
        description "Validate a technique pack through the full armor (schema, stratification, " \
                    "corpus guard). Installing needs a consent token and the operator's " \
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
          allowlist: {type: "string"},
          payload_file: {type: "string", description: "custom shellcode/payload bytes"}
        }, required: %w[binary facts_path allowlist])

        class << self
          include ::LictorMcp::ToolHelpers

          def call(binary:, facts_path:, allowlist:, technique: nil, payload_file: nil, server_context: nil)
            ::Lictor::Gates.allowlist(allowlist)
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
          rescue ::Lictor::Unauthorized => e
            error("UNAUTHORIZED: #{e.message}")
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
            # No allowlist gate: the scaffold touches no target - the
            # staging directory IS the control (the operator reviews
            # before anything is committed anywhere), and the trail
            # records the draft.
            facts = ::File.read(facts_path)
            result = ::Lictor::PayloadBuilder.build(binary: binary, facts: facts,
              technique: technique, out: ::File.join(::Dir.tmpdir, "lictor-payload-#{::Process.pid}.bin"))
            dest = ::Lictor::ExploitScaffold.scaffold(technique: technique, constants: result,
              repo_dir: staging_dir, author: "lictor-mcp scaffold (operator review required)")
            trail.record(run: ::SecureRandom.uuid, type: "scaffold", technique: technique,
              offset: result[:offset], ret: result[:ret_source], file: dest)
            respond(scaffolded: dest, review: "the operator reads and commits this file")
          rescue ::Lictor::Unauthorized => e
            error("UNAUTHORIZED: #{e.message}")
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
                    "records who proposed what and what changed. Requires an allowlist."
        input_schema(properties: {
          facts_path: {type: "string", description: "path to the base .facts file"},
          suggested_facts: {type: "string", description: "hypothesis facts, one predicate(\"atom\"). per line"},
          allowlist: {type: "string"}
        }, required: %w[facts_path suggested_facts allowlist])

        class << self
          include ::LictorMcp::ToolHelpers

          def call(facts_path:, suggested_facts:, allowlist:, server_context: nil)
            ::Lictor::Gates.allowlist(allowlist)
            result = ::Lictor::Suggestion.apply(base_facts: File.read(facts_path),
              suggested: suggested_facts, trail: trail, target: facts_path)
            respond(target: facts_path, delta: {
              added: result[:added],
              applicable_before: result[:applicable_before],
              applicable_after: result[:applicable_after],
              selected_before: result[:selected_before],
              selected_after: result[:selected_after]
            })
          rescue ::Lictor::Unauthorized => e
            error("UNAUTHORIZED: #{e.message}")
          rescue ::Augure::MalformedFact, ::Augure::UnknownPredicate => e
            error(e.message)
          end
        end
      end
    ].freeze

    def self.build
      ::MCP::Server.new(name: "lictor-mcp", version: ::LictorMcp::VERSION, tools: TOOLS).tap do |server|
        server.instructions = "lictor orchestrates the augure decision layer. All tools are " \
                              "server-side gated: the allowlist is the scope, execution needs " \
                              "a human-issued consent token (lictor authorize <target>)."
      end
    end
  end
end
