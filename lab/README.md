# The augure/lictor lab

A self-contained docker lab: one vulnerable service, one ronin exploit,
one command sequence that exercises the WHOLE pipeline - scan, profile,
decide, authorize, execute, report - with the flag as the proof.

**For the demo only. The target is ours; the exploit is ours; nothing
here touches a real target.**

## Layout

```
lab/
  docker-compose.yml          # the target: socat service + binary over http
  target/vuln_service.c       # no-PIE, no canary, NX ON; win() prints the flag
  target/flag.txt             # the proof
  ronin-repo/exploits/        # the operator's ronin exploit (discovered, never invented)
  setup.sh                    # installs ronin-exploits + registers the local repo
  demo.sh                     # replays the full pipeline
```

## The demo

```sh
sh setup.sh        # ronin toolchain + local repo
sh demo.sh         # scan -> profile -> plan -> authorize -> run -> report
```

What the demo shows, step by step:

1. `lictor scan 127.0.0.1 -a targets.yml` - nmap finds the service (trailed).
2. The binary is fetched and profiled (`augure-profile`): facts - NX on,
   no PIE, no canary, `vuln_hint: unsafe_func:strcpy`, `target_function: true`.
3. `lictor plan` - augure picks **ret2func** (pie off + win present) with
   the rule provenance. NOT shellcode (NX on): the decision layer's
   anti-reflex discipline.
4. `lictor authorize 127.0.0.1:9999` - the operator TYPES the target;
   a short-lived token is recorded.
5. `lictor run --executor ronin --consent-token <tok>` - the executor
   DISCOVERS `lab_ret2func_001` in the operator's repos (never invented),
   runs it: the banner's win address, padding, the ret gadget for stack
   alignment, the flag. Outcome success, trailed.
6. `lictor report` - the auditable engagement report with the executed
   steps and their provenance.

## The classic CTF gotchas this demo hits (on purpose)

- **movaps alignment**: the smashed saved-rbp misaligns rsp; the inner
  puts faults (`movaps` needs 16-byte alignment). win() realigns
  (`and $-16, %rsp`), or the exploit uses the ret gadget.
- **strcpy NUL truncation**: an 8-byte address cannot survive strcpy
  (the NULs truncate the copy). The 2-byte partial overwrite works:
  the original ret's high bytes are already right for a no-PIE target.
- **the service's own `input[n-1] = 0`**: it zeroes the last payload
  byte - the payload needs one filler byte after the significant ones.

These are the reasons the decision layer exists: the technique facts
(NX, no PIE, strcpy hint, target_function) decide ret2func BEFORE
anyone writes a byte of payload.
