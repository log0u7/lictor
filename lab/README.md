# The augure/lictor lab

A self-contained docker lab: **six vulnerable services, six different
fact bases, six different decisions from the same engine** - and one
tested exploit per target. The flag is the proof.

**For the demo only. The targets are ours; the exploits are ours;
nothing here touches a real target.**

## The six targets

| Target | Port | What makes it different | augure's decision | The lab exploit |
|---|---|---|---|---|
| ret2func | 9999 | win() present, no-PIE, no canary, NX ON | **ret2func** | `lab_ret2func_001` |
| ret2plt | 9998 | NO win(), but system@plt + a pop-rdi gadget announced | **ret2plt** | `lab_ret2plt_002` |
| shellcode | 9997 | NX OFF (-z execstack), the input buffer's address announced | **shellcode** | `lab_shellcode_003` |
| fmtstr | 9996 | printf(input) - the format IS the weapon; a hook pointer to write | **fmtstr_write** | `lab_fmtstr_004` |
| uaf_heap | 9995 | tcache UAF, the fn pointer lives ON the heap - the facts come from knowledge (suggest), not the profiler | **uaf_tcache** | the decision layer's recipe |
| orw | 9994 | seccomp: execve dies; the buffer address is the leak; served under `setarch -R` (the compose notes why) | **orw** | built by `lictor build orw` |

Same engine, six fact bases - stack, heap, format, filter - each with
its rule provenance. That is the product; the lab exists to show it.
The heap and seccomp targets demo the **suggest** flow: the facts the
profiler cannot see (a heap class, a filter) enter through the
operator's knowledge, and the decision moves.

## Layout

```
lab/
  docker-compose.yml          # one image, six socat services + http (seccomp:unconfined for setarch -R)
  targets/<name>/service.c    # each service: banner + its own vuln class
  targets/<name>/flag.txt     # each target has its own flag
  start.sh                    # http (acquisition) + 6 listeners (orw under setarch -R)
  ronin-repo/exploits/        # the operator's ronin exploits (discovered, never invented)
  setup.sh                    # installs ronin-exploits + registers the local repo
  demo.sh                     # replays the full pipeline for all six
```

## The demo

```sh
sh setup.sh        # ronin toolchain + local repo
sh demo.sh         # scan, then per target: acquire -> decide -> build -> run
```

What demo.sh does, per target:

1. `lictor scan 127.0.0.1` - nmap finds the six
   services; the scan is recorded.
2. `lictor acquire 127.0.0.1:80xx --from http://...` - the binary is
   downloaded, ELF-checked, profiled, recorded (the nmap → binary
   bridge).
3. `lictor plan target.facts` - augure reads the fact
   base and ranks: **a different technique per target**, with the rule
   provenance.
4. `lictor build <binary> --facts target.facts` - the offset is
   MEASURED (the cyclic pattern under the debugger) and the payload is
   assembled: measured padding + the fact-sourced return address.
5. `lictor run ... --executor ronin --payload payload.bin` - the closed
   loop; the executor DISCOVERS the lab exploit in the operator's repos
   (never invented), runs it; the outcome is recorded. The mirror is
   the analysis target: the local service gets profiled and built
   against, `lictor verify` proves the remote faults like the local
   model before anything runs against the remote.
6. `lictor report` - the auditable engagement report covering all six.

The honesty note: ret2func executes end-to-end with the BUILT payload
(`lictor build` measures the offset - 16, no brute-force - and the run
lands the real flag). The other three currently stop at the
recipe/attempt level - the classic CTF minutiae (ROP NUL truncation,
%hn slot alignment) are exactly the hard parts - and the system reports
them as failures instead of pretending. Before this build, ret2func's
own "success" was a lie: the exploit exited 0 whether or not the flag
came; it raises now. The exploits stay in the repo as the lab's test
harness - and after editing one, refresh ronin's repo cache
(`cp lab/ronin-repo/exploits/*.rb ~/.cache/ronin-repos/ronin-repo/exploits/`
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
