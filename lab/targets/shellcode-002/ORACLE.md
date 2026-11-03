# shellcode-002 - ORACLE

## Technique

NX OFF (execstack), PIE ON: the shellcode rides the stack; with PIE
the buffer's address shifts per boot, so the banner's buf leak is
load-bearing (the exploit aims the return slot at the leaked buffer's
address in the same connection - leak and strike in one round).
execve("/bin/sh") runs from the stack, the shell cats the flag.

## Build

```
gcc service.c -o shellcode-002 -fno-stack-protector -pie -fPIE -z execstack -O0
```

PIE on, stack canary off, GNU_STACK RWE (execstack). The banner hands
the buffer's runtime address (PIE-shifted per boot).

## Serve

socat on port 9986, EXEC mode, stderr forwarded. The service runs
from its own directory (the flag file is opened relative).

## Success output

The exploit is one-shot: the shellcode rides the read, the return
slot aims the leaked buffer address, execve("/bin/sh") runs, the
shell takes over. The shell then cats the flag file; stdout carries
exactly:

```
FLAG{mr5_shellcode_pie_stack}
```

The oracle regex matches the flag line (the shell's own prompt noise
is acceptable; the flag line is decisive).

## The lab exploit

`lab_shellcode_002` (named to sort before `lab_shellcode_003`, and
replicating its behaviour for the original no-PIE target): the
strcpy channel stops at the leaked buffer address's own NUL byte, so
the return slot lands on the exact leaked buffer; the sled's jmp skips
the embedded pointer and the execve("/bin/sh") stub runs from the
stack. The shell cats the flag over the same connection.
