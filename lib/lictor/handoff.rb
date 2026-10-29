# frozen_string_literal: true

require "augure"

module Lictor
  # Handoff mode: augure decided, Lictor prints the recipe and a human runs
  # it. No RPC, no daemon, no Metasploit install - the Ruby-native arsenal
  # (ronin-exploits 2.1 + rex gems) carries the execution, from gems.
  module Handoff
    # technique -> ronin mixin mapping. Verified against ronin-exploits
    # 1.1.1: the mixins ARE the framework vocabulary; the concrete exploit
    # comes from the operator's installed ronin repos (community exploits
    # are not bundled, so lictor never fabricates exploit names).
    RONIN_MIXINS = {
      "shellcode" => {mixin: "Binary", delivery: "RemoteTCP"},
      "ret2func" => {mixin: "Binary", delivery: "RemoteTCP"},
      "ret2plt" => {mixin: "Binary", delivery: "RemoteTCP"},
      "ret2libc" => {mixin: "Binary", delivery: "RemoteTCP"},
      "rop" => {mixin: "Binary", delivery: "RemoteTCP"},
      "srop" => {mixin: "Binary", delivery: "RemoteTCP"},
      "dlresolve" => {mixin: "Binary", delivery: "RemoteTCP"},
      "got_overwrite" => {mixin: "Binary", delivery: "RemoteTCP"},
      "stack_pivot" => {mixin: "Binary", delivery: "RemoteTCP"},
      "ret2csu" => {mixin: "Binary", delivery: "RemoteTCP"},
      "ret2plt_leak" => {mixin: "Binary", delivery: "RemoteTCP"},
      "fmtstr_leak" => {mixin: "FormatString", delivery: "RemoteTCP"},
      "fmtstr_write" => {mixin: "FormatString", delivery: "RemoteTCP"},
      "got_overwrite (fmtstr)" => {mixin: "FormatString", delivery: "RemoteTCP"},
      "heap_tcache" => {mixin: "Binary", delivery: "Local"},
      "heap_fastbin" => {mixin: "Binary", delivery: "Local"},
      "heap_overwrite" => {mixin: "Binary", delivery: "Local"}
    }.freeze

    module_function

    def recipe(technique)
      hint = RONIN_MIXINS.fetch(technique) do
        {mixin: nil, delivery: nil}
      end
      mixin_line = hint[:mixin] ? " # mixin: Ronin::Exploits::Mixins::#{hint[:mixin]}" : ""
      {
        technique: technique,
        runner: "ronin",
        mixin: hint[:mixin],
        console: "ronin-exploits run <exploit-name-from-your-repos> " \
                 "--technique #{technique}#{mixin_line}"
      }
    end

    def plan(facts:, seed: nil, priors: nil, packs: nil, technique: nil)
      decision = Augure::Pipeline.analyze(facts: facts, seed: seed, priors: priors, packs: packs)
      selected = technique || decision[:selected]
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
