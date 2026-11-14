# shellcode-eval2 - ORACLE

## Technique

shellcode: NX OFF (execstack), the input buffer is the payload. The
banner announces the buffer's address (where the payload lands, on
the stack); the exploit harvests it - a global .data buffer would not
carry the primitive (the .bss is not executable even under -z
execstack, and the copy destination is ASLR'd). execstack required.

## Build

```
gcc service.c -o shellcode-eval2 -fno-stack-protector -no-pie -z execstack -O0
```

no PIE, stack canary off, NX OFF (execstack).

## Serve

socat on port 20005, EXEC mode, stderr forwarded.

## Success output

FLAG: FLAG{mr6_shellcode_eval2_exec}
