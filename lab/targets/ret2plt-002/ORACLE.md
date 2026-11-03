# ret2plt-002 - ORACLE

## Technique

ret2plt with full ASLR (PIE ON): stage 1 leaks the HEAP POINTER
through puts@plt aimed at the .bss slot that holds it (the raw heap
address rides out as bytes); stage 2 rides the ret2plt write -
write@plt dumps the flag buffer that pointer names. No libc leak, no
system: both stages are pure PLT entries (the ret2plt discipline).
The banner hands the binary's own anchors (main, the gadgets) - the
PIE base falls out; the heap pointer rides the puts(&flag_ptr) chain.
The service loops: the leak round and the write round ride the same
overflow in one connection.

## Build

```
gcc service.c -o ret2plt-002 -fno-stack-protector -pie -fPIE -O0 -Wl,-z,now
```

PIE on, stack canary off, NX on, full RELRO (BIND_NOW). The flag
lives in a heap buffer the service fills at startup; the exploit
finds it via the leak stage.

## Serve

socat on port 9990, EXEC mode, stderr forwarded. The service runs
from its own directory (the flag file is opened relative).

## Success output

The exploit runs in two rounds on one connection:

1. Round 1: the chain calls puts(&GOT[read]) and returns to main -
   stdout carries the raw libc address bytes (6 bytes, then the
   banner re-prints as the loop restarts).
2. Round 2: the chain aims write@plt at the flag buffer (its address
   falls out of the leak stage); the flag rides stdout.

stdout carries exactly:

```
FLAG{mr5_ret2plt_aslr_write}
```

The oracle regex matches the flag line (the banner re-prints and the
leak's raw bytes are noise; the flag line is decisive).

## The lab exploit

`lab_ret2plt_leak_009` (the `ret2plt_leak` discovery binding; the
`lab_ret2libc_008` dispatch covers it too): round 1 puts(&flag_ptr)
leaks the heap pointer and returns into main, round 2 write(1, heap,
0x100) dumps the flag buffer - both stages ride the binary's own PLT,
no libc addresses anywhere. The `ret2plt_leak` build layout produces
the stage-1 chain (pop rdi; &flag_ptr; puts@plt) from the facts.
