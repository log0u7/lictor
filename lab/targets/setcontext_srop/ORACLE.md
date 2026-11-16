# setcontext_srop - ORACLE

## Technique

setcontext_srop: the sigreturn path has two doors - the classic
SROP frame and the setcontext gadget (offset +53/+61 in modern
glibc). Same primitive, fewer gadgets, no mprotect needed. Here the
exploit rides the classic door: pop rax=15, a libc `syscall; ret`
gadget, then the forged sigreturn frame rides the payload itself.

## Build

```
gcc service.c -o setcontext_srop -fno-stack-protector -no-pie -O0
```

no PIE, stack canary off, NX on, dynamic libc.

## Serve

socat on port 20106, EXEC mode, stderr forwarded.

## Success output

Shell: `cat /opt/target/setcontext_srop.flag`

## Exploit Contract

The overflow channel: `read(0, buf, 512)` into `buf[64]` - the
read channel crosses NUL-bearing qwords whole. The return slot
sits at offset 88 (buf[64] + 16 bytes of locals + saved rbp; the exploit measures it).

1. Read the served binary (http://host:8000/setcontext_srop) and
   take the addresses of `pop_rdi_asm`, `pop_rax_asm`, `staging`,
   GOT[puts] and puts@plt with nm (all static, no PIE).
2. Leak: `pop_rdi_asm` + GOT[puts] then puts@plt prints the raw
   libc pointer (puts stops at the pointer's high NULs - the low 6
   bytes ride out). The strike derives libc base, then system(),
   "/bin/sh" and the `syscall; ret` gadget offset.
3. Strike: `pop_rax_asm` + 15, then the syscall gadget, then the
   forged sigreturn frame rides the payload: rdi="/bin/sh",
   rip=system, rsp=staging, eflags=0x202, cs=0x33, everything else
   zero. rt_sigreturn restores the state - system("/bin/sh") fires.
4. The frame: 39 qwords after the syscall gadget (pretcode,
   uc_flags, uc_link, uc_stack, r8..r15, rdi, rsi, rbp, rbx, rdx,
   rax, rcx, rip, rsp, eflags, cs/gs/fs/ss, err, trapno, oldmask,
   cr2, fpstate, reserved1[8], sigmask). The sigmask qword MUST
   ride: the kernel reads it for set_current_blocked - a short
   payload dies on EFAULT.

## Flag

The service ships `setcontext_srop.flag` (relative to /opt/target).
The shell reads it.
