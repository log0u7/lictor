# callme-002 - ORACLE

## Technique

Call-me convention, 3-argument variant: THREE helper functions must
fire in the correct order (one, two, three), each with the (1,2,3)
argument triple (pop rdi; pop rsi; pop rdx; ret populates the
registers per helper). The helpers gate on each other - one arms the
sequence, two confirms it, three reads the flag. NO win() shortcut:
the helper sequence IS the win. The banner announces the three
helpers and the pop3 gadget. The copy is bounded by the read length
(memcpy): the chain carries NUL-bearing values (1, 2, 3 as qwords).

## Build

```
gcc service.c -o callme-002 -fno-stack-protector -no-pie -O0
```

no PIE, stack canary off, NX on. The banner hands the three helper
addresses and the pop3 gadget's address.

## Serve

socat on port 9989, EXEC mode, stderr forwarded. The service runs
from its own directory (the flag file is opened relative).

## Success output

The exploit is one-shot: the chain calls helper_one(1,2,3), then
helper_two(1,2,3), then helper_three(1,2,3). helper_three reads the
flag. stdout carries exactly:

```
one: OK
two: OK
FLAG: FLAG{mr5_callme_three_args}
```

(The "hello" echo is absent: the chain replaces the return path.)
The oracle regex matches the FLAG: line (the helper echoes are
recon; the FLAG: line is decisive).

## The lab exploit

`lab_callme_002` (named to sort before `lab_callme_005`, and
replicating its behaviour for the ROP Emporium target): the banner
hands the three helper addresses and the pop3 gadget - the chain fires
one/two/three in order, each with the (1, 2, 3) triple; the trailing
filler absorbs the service's input[n - 1] = 0. helper_three exits
inside the win path. The `rop` binding `lab_rop_011` dispatches to the
same chain.
