# ret2plt-eval2 - ORACLE

## Technique

ret2plt: no win(), system@plt exists, a benign call in main. The
harder twin announces NOTHING: no system@plt or gadget address. Both
are static (no PIE), so the exploit derives them from the binary
(objdump). The command string lives in .data. NX ON.

## Build

```
gcc service.c -o ret2plt-eval2 -fno-stack-protector -no-pie -O0
```

no PIE, stack canary off, NX on.

## Serve

socat on port 20003, EXEC mode, stderr forwarded.

## Success output

FLAG: FLAG{mr6_ret2plt_eval2_system}
