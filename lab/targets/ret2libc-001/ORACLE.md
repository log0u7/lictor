# ret2libc-001 - ORACLE

## Technique

Classic ret2libc, PIE ON: the ROP chain leaks a GOT entry through
puts@plt (the raw libc address rides out as bytes), derives the libc
base from the leak, then stage 2 rides system("/bin/sh") - the shell
cats the flag. The service loops: the leak round and the strike round
ride the same overflow in one connection.

## Build

```
gcc service.c -o ret2libc-001 -fno-stack-protector -pie -fPIE -O0
```

PIE on, stack canary off, NX on. The banner hands the binary's own
anchors (main, vuln, the pop-rdi gadget); libc stays hidden - the
leak must come from puts(GOT).

## Serve

socat on port 9982, EXEC mode, stderr forwarded. The service runs
from its own directory (the flag file is opened relative).

## Success output

The exploit runs in two rounds on one connection:

1. Round 1: the chain calls puts(&GOT[read]) and returns to main -
   stdout carries the raw libc address bytes (6 bytes, then the
   banner re-prints as the loop restarts).
2. Round 2: the chain aims pop rdi at libc's "/bin/sh", calls
   libc's system, the shell takes over.

The shell then cats the flag file; stdout carries exactly:

```
FLAG{mr5_ret2libc_leak_first}
```

The oracle regex matches the flag line (the shell's own prompt noise
is acceptable; the flag line is decisive).
