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

## The lab exploit

`lab_orw_002` (named to sort before `lab_orw_007`, and replicating its
behaviour for the original target): the banner's five gadgets (+4 past
each prologue) build the openat(AT_FDCWD, path, 0) / read(3, buf,
0x100) / write(1, buf, 0x100) / exit(0) chain - the .data anchors are
the measured fixed addresses (flag_path 0x404050, out_buf 0x404080).
No shell, no execve: the raw 0x100 bytes carry the flag line. The
`rop` binding `lab_rop_011` dispatches to the same chain.
