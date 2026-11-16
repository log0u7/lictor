# ret2vdso - ORACLE

## Technique

ret2vdso: the vDSO is mapped at a near-static offset for the
process's lifetime: gadgets in it survive PIE randomization of the
main image. A syscall-bearing page the loader itself mapped -
scarce gadgets, but exactly where the main binary has none.

## Build

```
gcc service.c -o ret2vdso -fno-stack-protector -pie -fPIE -O0
```

PIE, stack canary off, NX on. The main binary has NO syscall
gadget: the only syscall-bearing page is the vDSO.

## Serve

socat on port 20105, EXEC mode, stderr forwarded.

## Success output

Shell: `cat /opt/target/ret2vdso.flag`

## Exploit Contract

The overflow channel: `read(0, buf, 256)` into `buf[64]` - the
read channel crosses NUL-bearing qwords whole. The return slot
sits at offset 88 (buf[64] + 16 bytes of locals + saved rbp; the exploit measures it). The echo `puts(buf)` is
the leak oracle. socat forks: every connection is a fresh process
(leak rounds and the strike ride separate connections).

1. Leak libc: `[padding, pop3_asm, GOT[puts], puts@plt]` - the
   echo prints the raw libc pointer. The strike derives libc base,
   then `/bin/sh` (leak:sh_cmd).
2. Establish the vDSO base (vdso_base_establish): `pop3_asm` +
   `&environ` + `puts@plt` leaks the environ pointer (a stack
   address); each further leak round walks the stack up to the
   auxv - AT_SYSINFO_EHDR IS the vDSO base.
3. Gadget hunt (gadget_hunt): leak rounds against the vDSO pages
   dump the raw bytes - the `syscall; ret` pattern (0f 05 c3) and
   the pop rdi gadget come out of the hunt (leak:vdso_syscall,
   leak:vdso_pop_rdi).
4. Syscall hop (syscall_hop): the strike
   `[padding, pop3_asm, leak:sh_cmd, 0, 0, pop_rax_asm, 59,
   leak:vdso_syscall]` - rax=59 (SYS_execve), rdi="/bin/sh",
   rsi=rdx=0, the vDSO's syscall fires the shell.

## Flag

The service ships `ret2vdso.flag` (relative to /opt/target). The
shell reads it.
