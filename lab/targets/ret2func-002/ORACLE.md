# ret2func-002 - ORACLE

## Technique

Stack overflow behind a stack canary: the copy dumps 40 raw bytes
from the buffer (the canary and the saved rbp ride out with it), the
exploit restores the canary intact in the strike round and aims
win(). The banner hands win()'s address (the target); the canary is
the constraint. The service loops: the leak round and the strike
round ride the same overflow in one connection.

## Build

```
gcc service.c -o ret2func-002 -fstack-protector-strong -no-pie -O0
```

Stack canary ON, no PIE, NX on. The canary's first byte is 0x00 (the
glibc layout) - the memcpy-bounded copy carries it whole.

## Serve

socat on port 9985, EXEC mode, stderr forwarded. The service runs
from its own directory (the flag file is opened relative).

## Success output

The exploit runs in two rounds on one connection:

1. Round 1: the copy's dump rides out the canary (40 raw bytes: 8
   buffer + 8 canary + 8 saved rbp + 8 return slot + 8 more).
2. Round 2: the strike restores the leaked canary, overwrites the
   return slot with win()'s address; the canary check passes, win()
   runs.

win() prints exactly:

```
FLAG: FLAG{mr5_canary_leak_then_win}
```

The oracle regex matches the FLAG: line (the service's own banner and
the dump's raw bytes are noise; the FLAG: line is decisive).

## The lab exploit

`lab_ret2func_000` (named to sort before `lab_ret2func_001`, whose
offset brute force cannot cross the canary): round 1 rides the 40-byte
raw dump out (the canary's NUL crosses whole) and parses the canary
from dump[8:16]; round 2 restores it verbatim, parks a dummy saved rbp
and aims the return slot at win(). The banner's win() address is the
target; the exploit is banner-driven, the built payload is ignored
here (a canary-smashing payload would only trip the check).
