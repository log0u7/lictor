# ret2libc-eval2 - ORACLE

## Technique

ret2libc: PIE ON, the ROP chain leaks a GOT entry through puts@plt,
derives the libc base, then stage 2 rides system("/bin/sh"). The
harder twin announces NOTHING (no main/vuln/rdi addresses); the
exploit leaks the base at runtime through the overflow. The service
loops: leak round then strike round in one connection.

## Build

```
gcc service.c -o ret2libc-eval2 -fno-stack-protector -pie -fPIE -O0
```

PIE on, stack canary off, NX on.

## Serve

socat on port 20006, EXEC mode, stderr forwarded.

## Success output

FLAG: FLAG{mr6_ret2libc_eval2_two_stage}
