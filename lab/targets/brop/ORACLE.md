# brop - ORACLE

## Technique

brop: blind ROP against a remote service. The binary announces
NOTHING: no win function, no gadget addresses, no banner. The
exploit measures the offset remotely (crash/no-crash), finds the
stop gadget and the pop rdi BROP gadget byte by byte, then leaks
libc via puts(GOT[puts]) and strikes with system("/bin/sh").

## Build

```
gcc service.c -o brop -fno-stack-protector -no-pie -O0
```

no PIE, stack canary off, NX on, dynamic libc.

## Serve

socat on port 20100, EXEC mode, stderr forwarded.

## Success output

Shell: `cat /opt/target/brop.flag`

## Exploit Contract

The overflow channel: `read(0, buf, 256)` into `buf[64]` - the
read channel crosses NUL-bearing qwords whole. The return slot
sits at offset 88 (buf[64] + 16 bytes of locals + saved rbp; the exploit measures it).

1. The echo `puts(buf)` is the only output: the crash/no-crash
   detector during the offset walk, and the leak oracle once the
   BROP gadget is found (return to `pop rdi; ret` + address ->
   puts prints the raw bytes).
2. Stop gadget: a `ret`-only address that hangs the connection
   (the service loops forever if it lands there). The BROP gadget
   is `pop rdi; ret` (static, no PIE, byte 0x401256): the exploit
   probes byte by byte.
3. Leak: `pop rdi; GOT[puts]` then `puts@plt` prints the raw libc
   pointer. The strike derives libc base from the leak, then
   system("/bin/sh") - the layout `[padding, measured_offset],
   [chain, "gadget:pop_rdi_ret", "leak:binsh", "leak:system"]`.
4. No built-in fires: nothing in the binary announces the win.

## Flag

The service ships `brop.flag` (relative to /opt/target). The shell
reads it.
