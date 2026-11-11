# shellcode-eval2 - ORACLE

## Technique

shellcode: NX OFF (execstack), the input buffer is the payload. The
harder twin announces NOTHING: no buffer address. The buffer is a
global, so its address is static (no PIE) and the exploit derives it
from the binary. execstack is required.

## Build

```
gcc service.c -o shellcode-eval2 -fno-stack-protector -no-pie -z execstack -O0
```

no PIE, stack canary off, NX OFF (execstack).

## Serve

socat on port 20005, EXEC mode, stderr forwarded.

## Success output

FLAG: FLAG{mr6_shellcode_eval2_exec}
