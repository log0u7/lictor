# uaf-eval2-001 - ORACLE

## Technique

Use-after-free on a tcache chunk whose function pointer lives on the
heap. The harder twin announces NOTHING: no chunk address. The menu
is unchanged ([n]ew [p]aint [g]o [f]ree [x]it) and the exploit still
takes the tcache-reuse path (free, then a fresh new() re-mounts the
same chunk before the paint wins). The chunk address is not needed:
the exploit drives the menu by letters.

## Build

```
gcc service.c -o uaf-eval2-001 -fno-stack-protector -no-pie -O0
```

no PIE, stack canary off, NX on.

## Serve

socat on port 20000, EXEC mode, stderr forwarded.

## Success output

FLAG: FLAG{uaf_eval2_reuse_paints_sketch}
