# orw-eval2 - ORACLE

## Technique

ORW (Open-Read-Write) with seccomp filter (allow: read(0) write(1) openat(257) close(3) exit(60) exit_group(231)).
The filter kills execve, the orw chain reads the flag.
NX stays ON - the shellcode must go through a writable + executable page: compiled -z execstack.

The harder twin properties:
1. NO BANNER LEAKS: no filter, no addresses, no win() announced.
2. PIE ON: the exploit must derive the code base at runtime.

Exploit contract:
1. Leak the buffer address (the shellcode slot) and the PIE base at runtime via format string walk.
2. Build the orw shellcode on the fly (openat/read/write/close/exit).
3. The shellcode lands in input[] on the executable stack (execstack).

## Build

```
gcc service.c -o orw-eval2 -fno-stack-protector -no-pie -O0 -z execstack
```

no PIE, stack canary off, NX OFF (the shellcode needs a writable + executable page). The banner announces NOTHING.

## Serve

socat on port 20002, EXEC mode, stderr forwarded. The service runs from its own directory (the flag file is opened relative).

## Success output

FLAG: FLAG{orw_eval2_shellcode_chain}

## Exploit Contract

The service provides a format string bug in the input handling.
The exploit must:
1. Leak a code pointer (PIE base) via format string walk.
2. Leak the buffer address (where shellcode lands).
3. Build and send the orw shellcode (openat/read/write/close/exit).
4. The shellcode executes and prints the flag.
