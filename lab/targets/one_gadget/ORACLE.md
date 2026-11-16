# one_gadget - ORACLE

## Technique

one_gadget: the single-qword strike. The exploit leaks libc via
puts(GOT[puts]), picks the one_gadget (execve("/bin/sh", ...) with
its constraint), and lands it on the return slot. No chain, no
/bin/sh string hunt.

## Build

```
gcc service.c -o one_gadget -fno-stack-protector -no-pie -O0
```

no PIE, stack canary off, NX on, dynamic libc.

## Serve

socat on port 20101, EXEC mode, stderr forwarded.

## Success output

Shell: `cat /opt/target/one_gadget.flag`

## Exploit Contract

The overflow channel: `read(0, buf, 256)` into `buf[64]` via
memcpy semantics - the read channel crosses NUL-bearing qwords
whole. The return slot sits at offset 88 (buf[64] + 16 bytes of locals + saved rbp; the exploit measures it).

1. The banner `ready` is the only output. Leak: `pop_rdi_asm` +
   GOT[puts] then puts@plt prints the raw libc pointer - the
   exploit derives libc base from the leak.2. one_gadget: the exploit picks the execve("/bin/sh", ...) gadget
   that fits the stack state, lands it on the return slot
   (layout `[padding, measured_offset], [qword, "leak:one_gadget"]`).
3. The constraint: the one_gadget wants the stack BEHIND the return
   slot zeroed - the exploit parks zeros after the qword (the read
   channel crosses NULs whole).
4. No built-in fires: no win function, no gadget addresses (the
   `ready` banner names nothing).

## Flag

The service ships `one_gadget.flag` (relative to /opt/target). The
shell reads it.
