# orw-002 - ORACLE

## Technique

open/read/write ROP behind a STRICT seccomp filter: the filter allows
ONLY open/openat/read/write/exit (no execve, no close, no mprotect).
The flag is reached through the pure syscall chain [openat, read,
write, exit]; execve dies with SIGSYS. The banner announces the
gadgets (pop rdi/rsi/rdx/rax + syscall) - the recon convenience; the
path string and the read buffer live in the binary's .data at fixed
addresses (no-PIE). NX ON - no shellcode shortcut either.

## Build

```
gcc service.c -o orw-002 -fno-stack-protector -no-pie -O0
```

no PIE, stack canary off, NX on (no execstack), seccomp filter
installed at runtime (the container runs with seccomp:unconfined so
the prctl set-up survives).

## Serve

socat on port 9988, EXEC mode, stderr forwarded. The service runs
from its own directory (the path string is relative). The openat fd
is 3 (fds 0/1/2 are the socket; socat EXEC with stderr forwarded).

## Success output

The exploit is one-shot: the chain runs openat(AT_FDCWD,
"orw-002.flag", 0), read(3, out_buf, 0x100), write(1, out_buf, n),
exit. stdout carries exactly:

```
FLAG{mr5_orw_strict_filter}
```

The oracle regex matches the flag line (the service's own banner and
the "hello" echo are noise; the flag line is decisive).
