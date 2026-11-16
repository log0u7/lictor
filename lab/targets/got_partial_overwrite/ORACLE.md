# got_partial_overwrite - ORACLE

## Technique

got_partial_overwrite: partial RELRO leaves the GOT writable.
Overwrite ONLY the low bytes of GOT[printf] so the imported
function lands on win(). Two bytes beat a leak when PIE keeps the
page fixed - here no PIE keeps the whole GOT address static.

## Build

```
gcc service.c -o got_partial_overwrite -fno-stack-protector -no-pie -O0
```

no PIE, stack canary off, NX on, PARTIAL RELRO (default gcc: GOT
writable), dynamic libc.

## Serve

socat on port 20102, EXEC mode, stderr forwarded.

## Success output

FLAG: FLAG{mr7_got_partial_overwrite_two_bytes}

## Exploit Contract

The write primitive: the service loops `read(0, buf, 200)` then
`printf(buf)` - the format string IS the write primitive (%n).
The loop gives the write a second call to land on.

1. Read the served binary (http://host:8000/got_partial_overwrite)
   and take the GOT[printf] address and win() with nm (all static,
   no PIE). Partial RELRO: the GOT entry is writable.
2. Write stage (exploit's job, not a static byte layout): compose
   the %n payload that lands win's low 2 bytes on GOT[printf] -
   the entry stays a valid PLT-trampoline low half (the high bytes
   of the resolved printf keep the frame).
3. The next loop iteration calls win through the hijacked GOT
   entry: win reads the flag and exits.
4. No return-slot overwrite: the format string IS the write.

## Flag

The service opens `got_partial_overwrite.flag` (relative to
/opt/target).
