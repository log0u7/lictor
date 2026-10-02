# frozen_string_literal: true

require "augure"

module Lictor
  # Handoff mode: augure decided, Lictor prints the recipe and a human runs
  # it. No RPC, no automated fire - the audit-friendly default.
  module Handoff
    # technique -> Metasploit module mapping. Techniques without a faithful
    # module mapping hand off as "manual" with the augure provenance.
    MODULES = {
      "shellcode" => "exploit/multi/handler",
      "ret2libc" => "exploit/multi/handler",
      "rop" => "exploit/multi/handler",
      "ret2plt" => "exploit/multi/handler",
      "ret2func" => "exploit/multi/handler",
      "srop" => "exploit/multi/handler",
      "got_overwrite" => "exploit/multi/handler",
      "dlresolve" => "exploit/multi/handler",
      "fmtstr_write" => "auxiliary/gather/fmtstr_write",
      "ret2plt_leak" => "auxiliary/gather/leak",
      "fmtstr_leak" => "auxiliary/gather/leak"
    }.freeze

    module_function

    def recipe(technique)
      module_name = MODULES.fetch(technique, "manual")
      console =
        if module_name == "manual"
          "# manual handoff: #{technique} (see provenance)"
        else
          "msfconsole -x 'use #{module_name}' # technique=#{technique}"
        end
      {technique: technique, module: module_name, console: console}
    end

    def plan(facts:, seed: nil)
      decision = Augure::Pipeline.analyze(facts: facts, seed: seed)
      selected = decision[:selected]
      {
        applicable: decision[:applicable],
        ranking: decision[:ranking],
        selected: selected,
        recipe: selected ? recipe(selected) : nil,
        explain: decision[:explain]
      }
    end
  end
end
