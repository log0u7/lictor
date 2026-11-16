# ret2partial_overwrite - ORACLE

## Technique

ret2partial_overwrite: the NO-LEAK fallback. PIE randomizes
pages, not the low 12 bits: overwrite ONLY the low 2 bytes of the
saved return address to hop onto win(). No leak needed when the
canary is absent.

## Build

```
gcc service.c -o ret2partial_overwrite -fno-stack-protector -static-pie -O0
```

static PIE (no libc, no PLT, no leak primitives), stack canary
off, NX on.

## Serve

socat on port 20103, EXEC mode, stderr forwarded.

## Success output

FLAG: FLAG{mr7_ret2partial_overwrite_page_hop}

## Exploit Contract

The overflow channel: `read(0, buf, 256)` into `buf[64]` via
memcpy semantics - the read channel crosses NUL-bearing qwords
whole, and a 2-byte partial rides it whole (the high 6 bytes of
the saved RIP stay original). The return slot sits at offset 88
(buf[64] + 16 bytes of locals + saved rbp; the exploit measures
it).

1. Read the served binary (http://host:8000/ret2partial_overwrite)
   and take win()'s file offset with nm (static PIE: the file
   offsets ARE the fact base - no leak primitive exists).
2. The page hop: the saved RIP's low 2 bytes are replaced with
   win()'s low 2 bytes - 4 bits of the base stay random (16 page
   candidates). The exploit probes the candidates
   (layout `[padding, measured_offset], [word, "sym:win"]`, the
   word slot lands win's low 16 bits; the probe loop varies the
   page bits).
3. The hop lands on win(): win reads the flag and exits.
4. No built-in fires: no win announcement, no banner, no leak.

## Flag

The service opens `ret2partial_overwrite.flag` (relative to
/opt/target).
