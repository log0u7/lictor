# srop-001 - ORACLE

## Technique

Sigreturn Oriented Programming (SROP): the binary carries a sigreturn
gadget (mov rax, 15; syscall) - the banner announces it. The exploit
crafts an rt_sigreturn frame on the stack (rax=SYS_execve=59,
rdi="/bin/sh", rsi=0, rdx=0), rets into the gadget, and the kernel
restores the WHOLE register state from the frame: execve("/bin/sh")
runs in one pivot. The banner hands the gadget's and the "/bin/sh"
string's addresses (no-PIE: both are fixed). NX ON, stack canary off.

## Build

```
gcc service.c -o srop-001 -fno-stack-protector -no-pie -O0
```

no PIE, stack canary off, NX on. The frame is the weapon (the
sigreturn syscall restores rax/rdi/rsi/rdx/rsp/rip from the forged
frame); the gadget is the trigger.

## Serve

socat on port 9991, EXEC mode, stderr forwarded. The service runs
from its own directory (the flag file is opened relative).

## Success output

The exploit is one-shot: the forged sigreturn frame rides the read,
the ret lands on the gadget, the kernel restores the frame (execve,
"/bin/sh", NULL, NULL), the shell takes over. The shell then cats the
flag file; stdout carries exactly:

```
FLAG{mr5_srop_sigreturn_frame}
```

The oracle regex matches the flag line (the shell's own prompt noise
is acceptable; the flag line is decisive).
