# jop - ORACLE

## Technique

jop: the indirect transfer rides a REGISTER, not the stack. The
vuln's return value lands in rax; the pivot gadget
`xchg rsp, rax; ret` consumes it. The exploit stages the fake
stack in .bss (dispatcher_target), then overflows: the return slot
takes the pivot gadget, the seed qword (the slot behind the
return slot) takes the fake-stack address and lands in rax. The
pivot lands rsp on the fake stack, its head ret fires the staged
win.

## Build

```
gcc service.c -o jop -fno-stack-protector -no-pie -O0
```

no PIE, stack canary off, NX on.

## Serve

socat on port 20104, EXEC mode, stderr forwarded.

## Success output

FLAG: FLAG{mr7_jop_register_pivot}

## Exploit Contract

The overflow channel: `read(0, buf, 256)` into `buf[64]` - the
second read (the overflow round) fires the return. The seed qword
rides the slot behind the return slot (buf+96, rbp+0x10) - the
vuln returns it into rax; the return slot sits at offset 88
(buf[64] + 16 bytes of locals + saved rbp).

1. Read the served binary (http://host:8000/jop) and take the
   addresses of `pivot_asm` (xchg rsp, rax; ret), `win` and
   `dispatcher_target` (.bss) with nm (all static, no PIE).
2. Stage 1 (the staging read): send 4104 bytes - 4096 filler +
   the win qword at the end. The read lands in .bss:
   dispatcher_target[4096] = win. The seed address is
   `dispatcher_target + 4096` (the address of the win pointer).
3. Stage 2 (the overflow): build the layout
   `[padding, measured_offset], [chain, "gadget:xchg_rsp_rax",
   "sym:dispatcher_target+4096"]` - the pivot gadget lands on the
   return slot, the seed qword rides the slot behind the return
   slot. The vuln returns the seed into rax: the pivot sets rsp =
   rax = the fake stack, its head ret fires win.
4. win runs on the .bss fake stack (the slack below the seed hosts
   its own frames): it reads the flag and exits.
5. No built-in fires: no win announcement, no banner, no addresses.

## Flag

The service opens `jop.flag` (relative to /opt/target).
