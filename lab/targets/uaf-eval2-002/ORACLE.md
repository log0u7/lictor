# uaf-eval2-002 - ORACLE

## Technique

Use-after-free on a tcache chunk whose function pointer lives on the
heap (the SECOND eval twin's harder sibling). Menu order [f]ree
first; the brush pointer sits at +32 in a 40-byte struct. No
address leak: the exploit drives the menu by letters and takes the
tcache-reuse path.

## Build

```
gcc service.c -o uaf-eval2-002 -fno-stack-protector -no-pie -O0
```

no PIE, stack canary off, NX on.

## Serve

socat on port 20001, EXEC mode, stderr forwarded.

## Success output

FLAG: FLAG{uaf_eval2_reuse_paints_board}
