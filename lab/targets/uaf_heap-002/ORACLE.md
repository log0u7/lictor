# uaf_heap-002 - ORACLE

## Technique

Use-after-free on a safe-linked tcache: glibc's tcache MANGLES its
next pointers (PROTECT_PTR = ((pos) >> 12) ^ (ptr)) - after the free,
the chunk's first word holds the mangled next (a naive read sees
garbage, a naive poison lands nowhere). The edit still lands through
the dangling pointer: the exploit writes the fn slot straight (the
mangling is irrelevant to this path - the pointer was not poisoned,
it was overwritten). The alloc banner leaks the chunk address (the
mangling's pos); win() runs through the dangling fn.

## Build

```
gcc service.c -o uaf_heap-002 -fno-stack-protector -no-pie -O0
```

no PIE, stack canary off, NX on. The heap is the weapon; the stack
stays boring.

## Serve

socat on port 9987, EXEC mode, stderr forwarded. The service runs
from its own directory (the flag file is opened relative).

## Success output

The exploit is menu-driven (1=alloc 2=free 3=edit 4=call):

1. alloc: the service prints `alloc: 0x<chunk addr>` (the recon).
2. free: the chunk lands in the tcache, the pointer stays (the UAF).
3. edit: the exploit writes the win() address (hex) into the freed
   chunk's fn slot (straight through the dangling pointer - the
   safe-linked next in there is the mangling the exploit bypasses).
4. call: the service calls the (now-win) fn; win() runs.

win() prints exactly:

```
FLAG: FLAG{mr5_uaf_safe_linking}
```

The oracle regex matches the FLAG: line (the menu's echoes are noise;
the FLAG: line is decisive).
