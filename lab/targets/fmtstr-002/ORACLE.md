# fmtstr-002 - ORACLE

## Technique

Format string on a PIE binary: the leak comes first (the format walk
prints the stack - the anchor slot holds a binary pointer, the PIE
base falls out), the write comes second (%n aims the hook pointer,
win() runs). The banner hands nothing - the leak IS the recon. The
service loops: the leak round and the write round ride the same
format bug in one connection.

## Build

```
gcc service.c -o fmtstr-002 -fno-stack-protector -pie -fPIE -O0
```

PIE on, stack canary off, NX on, full RELRO (BIND_NOW). The hook
pointer starts NULL; the %n write is the exploit's weapon.

## Serve

socat on port 9984, EXEC mode, stderr forwarded. The service runs
from its own directory (the flag file is opened relative).

## Success output

The exploit runs in two rounds on one connection:

1. Round 1: the format walk (%p chain) prints the stack - the leaked
   anchor reveals the PIE base (the hook pointer's runtime address
   falls out of the leak).
2. Round 2: the format write (%n) lands the win() address into the
   hook slot; the service calls it and win() runs.

win() prints exactly:

```
FLAG: FLAG{mr5_fmtstr_pie_leak_write}
```

The oracle regex matches the FLAG: line (the service's own banner and
the format walk's output are noise; the FLAG: line is decisive).

## The lab exploit

`lab_fmtstr_leak_002` / `lab_fmtstr_write_002` (the discovery bindings
that sort before the original fmtstr aliases): round 1 leaks the input
buffer (arg 1) and the anchor slot (arg 39, holding &the_hook) with a
%p walk - the PIE base falls out; round 2 fires ONE printf with four
positional %hn writes rebuilding win() in main's saved return slot
(the 16-bit words sorted, the gaps padded with %1$Nc, the addresses
riding after the NUL-terminated format at slots 13-16). EOF makes main
return into win(). The original fmtstr target's banner (hook()/win()
addresses) still rides the parent's %hhn craft.
