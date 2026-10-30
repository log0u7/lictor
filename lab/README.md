# The augure/lictor lab

A self-contained docker lab: **eleven services (eight targets + three
hardened mirrors), eight fact bases, eight decisions from the same
engine**. Seven targets land real flags deterministically through the
lab exploits and the built payload (ret2func, ret2plt, shellcode,
fmtstr, orw, callme, ret2csu); ret2plt's chain rides the read channel,
whose copy is bounded by the read length, so the NUL-bearing addresses
cross whole and rdi aims the service's own command string (30/30
connections). The heap target decides and hands off loyally (its craft
is the operator's exercise). The flag is the proof where the run
reaches it.

**For the demo only. Our targets are ours; the exploits are ours;
nothing here touches a real target.** The callme and ret2csu binaries
are the ROP Emporium challenge files (public practice binaries, used
as-is, no source), vendored under `targets/` with their provenance in
this file.

## The eight targets

| Target | Port | What makes it different | augure's decision | The lab exploit |
|---|---|---|---|---|
| ret2func | 9999 | win() present, no-PIE, no canary, NX ON | **ret2func** | `lab_ret2func_001` |
| ret2plt | 9998 | NO win(), but system@plt + a pop-rdi gadget announced | **ret2plt** | `lab_ret2plt_002` |
| shellcode | 9997 | NX OFF (-z execstack), the input buffer's address announced | **shellcode** | `lab_shellcode_003` |
| fmtstr | 9996 | printf(input) - the format IS the weapon; a hook pointer to write | **fmtstr_write** | `lab_fmtstr_004` |
| uaf_heap | 9995 | tcache UAF, the fn pointer lives ON the heap - the facts come from knowledge (suggest), not the profiler | **uaf_tcache** | the decision layer's recipe |
| orw | 9994 | seccomp: execve dies; the buffer address is the leak; served under `setarch -R` (the compose notes why) | **orw** | built by `lictor build orw` |
| callme | 9993 | ROP Emporium, binary-only: three PLT calls with the magic triple; the pack teaches the layout, the profiler learns `pop rsi; pop r15; ret` | **callme** | `lab_callme_005` |
| ret2csu | 9992 | ROP Emporium, binary-only: no arg gadgets at all - the csu pair + the DT_FINI no-op call; the win_symbol trap (an import is not a win here) lives in the profiler's tests | **ret2csu_v2** | `lab_ret2csu_v2_006` |

Same engine, eight fact bases - stack, heap, format, filter, and the
binary-only ROP Emporium pair - each with its rule provenance. That is
the product; the lab exists to show it. The heap target demos the
**suggest** flow: the facts the profiler cannot see (a heap class)
enter through the operator's knowledge, and the decision moves.

## Layout

```
lab/
  docker-compose.yml          # one image, ELEVEN socat services + http (seccomp:unconfined for setarch -R)
  targets/<name>/service.c    # each service: banner + its own vuln class
  targets/<name>/flag.txt     # each target has its own flag
  targets/callme/             # ROP Emporium, binary-only: the binary, its lib, the encrypted flag + keys, the run.sh wrapper
  targets/ret2csu/            # same shape: the binary, libret2csu.so, the encrypted flag + key, the run.sh wrapper
  start.sh                    # http (acquisition) + 11 listeners (orw under setarch -R, the emporium pair via the wrappers)
  purple.sh                   # the purple loop: the coverage flips + the defender view
  Dockerfile                  # the targets AND the hardened matrix
  ronin-repo/exploits/        # the operator's ronin exploits (discovered, never invented)
  setup.sh                    # installs ronin-exploits + registers the local repo
  demo.sh                     # replays the chain: run for the seven executable targets
                              # (the oracle is the target's own flag), decide + handoff for uaf_heap
```

## The demo

```sh
sh setup.sh        # ronin toolchain + local repo
sh demo.sh         # scan, then per target: acquire -> decide -> build -> run
                   # (the vuln facts come off the binary; ret2csu's lib-side
                   # overflow and uaf_heap's heap class still enter via suggest)
                   # (run for the five stack targets, uaf_heap stops at plan/build)
```

What demo.sh does, per target:

1. `lictor scan 127.0.0.1` - nmap finds the eight
   services; the scan is recorded.
2. `lictor acquire 127.0.0.1:9999 --from http://127.0.0.1:8000/<name>` -
   the binary is downloaded, ELF-checked, profiled, recorded (the nmap →
   binary bridge; the http server is port 8000).
3. `lictor plan target.facts` - augure reads the fact
   base and ranks: **a different technique per target**, with the rule
   provenance.
4. `lictor build <binary> --facts target.facts` - the offset is
   MEASURED (the cyclic pattern under the debugger) and the payload is
   assembled: measured padding + the fact-sourced return address.
5. `lictor run ... --executor ronin --payload payload.bin --flag-regex ...` -
   the closed loop; the executor DISCOVERS the lab exploit in the
   operator's repos (never invented), runs it; the outcome is recorded.
   The mirror is the analysis target: the local service gets profiled
   and built against - run `lictor verify <target> --input crash-input.bin`
   yourself before anything runs against a real remote (the demo does
   not: the lab IS the mirror and the remote in one).
6. `lictor report` - the auditable engagement report covering all eight.

The honesty note: seven targets execute end-to-end (the built payload
or the discovered exploit lands the real flag, the oracle is the
target's own flag); uaf_heap stops at the handoff by design - the heap
craft is the operator's exercise, and the system reports the handoff
as a handoff instead of pretending. The exploits stay in the repo as
the lab's test harness - and after editing one, refresh ronin's repo
cache (`cp lab/ronin-repo/exploits/*.rb ~/.cache/ronin-repos/ronin-repo/exploits/`
or `ronin-repos update`), or ronin keeps serving the old copy.

## The classic CTF gotchas in this lab (on purpose)

- **movaps alignment**: the smashed saved-rbp misaligns rsp; inner
  puts faults. win() realigns (`and $-16, %rsp`).
- **strcpy NUL truncation**: 8-byte addresses cannot survive strcpy -
  the 2-byte/3-byte partial overwrite is the way (the original ret's
  high bytes are already right for a no-PIE target).
- **the service's own `input[n-1] = 0`**: it zeroes the last payload
  byte - the payload needs one filler byte after the significant ones.
- **the call-argument registers**: x86_64 passes arguments in RDI...
  a ret2plt needs a `pop rdi; ret` gadget - the lab's tiny binaries
  lack it (the banner announces the one service provides).

These are the reasons the decision layer exists: the technique facts
(NX, no PIE, strcpy hint, target_function) decide ret2func BEFORE
anyone writes a byte of payload.

## The purple side: the hardening matrix

The same sources compiled under full hardening (canary, PIE, full
RELRO, FORTIFY) are served on the 889x ports (`ret2func_h` 8899,
`ret2plt_h` 8898, `shellcode_h` 8897): acquire a hardened mirror and
the decision's applicable set shrinks. `sh purple.sh` replays the
purple loop: the corpus flips (`augure coverage`) + the defender view
of an attack trail (`lictor report --defender`). The blue team gets
its scorecard; the SOC gets the timeline and the per-technique
observables straight from the packs' `detection:` sections.

## The bench

`sh purple.sh` is the purple loop; `sh bench.sh` exports the
TELEMETRY: the demo replay's trail as the artifact the LLM benchmarks
shape wants (the tasks, the actions, the feedback - `lictor run` is
the interactive environment; NYU CTF Bench / InterCode are the
readers). The summary is `lictor/bench@1`, predictions with
provenance, never field results.
