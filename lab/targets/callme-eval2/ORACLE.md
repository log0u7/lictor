# callme-eval2 - ORACLE

## Technique

callme: chain three gated foreign calls (vault_arm, vault_fire,
vault_open) in order with the right magic triples. The harder twin
announces NOTHING: no stage/gadget/probe addresses (all static, no
PIE). One buffer overflow builds the whole chain via the pop3 gadget.

## Build

```
gcc service.c -o callme-eval2 -fno-stack-protector -no-pie -O0
```

no PIE, stack canary off, NX on.

## Serve

socat on port 20007, EXEC mode, stderr forwarded.

## Success output

FLAG: FLAG{mr6_callme_eval2_three_gates}
