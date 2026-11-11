# ret2func-eval2 - ORACLE

## Technique

ret2func: win() present, unbounded strcpy. The harder twin announces
NOTHING: no win() address. win() is static (no PIE), so the exploit
derives it from the binary. NX ON.

## Build

```
gcc service.c -o ret2func-eval2 -fno-stack-protector -no-pie -O0
```

no PIE, stack canary off, NX on.

## Serve

socat on port 20004, EXEC mode, stderr forwarded.

## Success output

FLAG: FLAG{mr6_ret2func_eval2_win}
