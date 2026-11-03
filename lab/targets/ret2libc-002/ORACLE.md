# ret2libc-002 - ORACLE

## Technique

ret2libc WITHOUT a leak: the build is -static -no-pie, so system and
the "/bin/sh" string both live at fixed addresses (baked in at build
time). The exploit resolves both offline from the binary, then the
chain is one pop rdi + one system call - no leak stage, no recon
round trip.

## Build

```
gcc service.c -o ret2libc-002 -fno-stack-protector -no-pie -O0 -static
```

Static libc baked in, no PIE, stack canary off, NX on. The banner
hands system's and the string's fixed addresses (what offline recon
would find); the craft is the chain, not the leak.

## Serve

socat on port 9983, EXEC mode, stderr forwarded. The service runs
from its own directory (the flag file is opened relative).

## Success output

The strike is one-shot: the chain aims pop rdi at "/bin/sh", calls
system, the shell takes over. The shell then cats the flag file;
stdout carries exactly:

```
FLAG{mr5_ret2libc_no_leak_static}
```

The oracle regex matches the flag line (the shell's own prompt noise
is acceptable; the flag line is decisive).

## The lab exploit

`lab_ret2libc_008` (and its `rop` binding `lab_rop_011`): the banner
hands system, the /bin/sh string and the pop-rdi gadget - the strike is
one pop rdi + one system call, no leak round. The shell cats the flag.
