# orw-eval2 - ORACLE

## Technique

ORW (Open-Read-Write) with a seccomp filter that allows read(0),
write(1), openat(257), close(3), exit(60), exit_group(231). open(2) is
NOT allowed and execve(59) dies with SIGSYS: the chain must use
openat.

The harder twin properties:

1. NO BANNER: no filter, no addresses, no win() announced.
2. openat-ONLY filter: the ROP chain's first syscall is forced.
3. NX ON: the payload is a ROP chain, not shellcode.

## Build

```
gcc service.c -o orw-eval2 -fno-stack-protector -no-pie -O0
```

no PIE (so the .data anchors and the gadget symbols are static), stack
canary off, NX on.

## Serve

socat on port 20002, EXEC mode, stderr forwarded. The service runs from
/opt/target (the flag file is opened relative).

## Success output

FLAG: FLAG{orw_eval2_shellcode_chain}

## Exploit Contract

The overflow channel: `vuln_copy` copies the read length with memcpy
(not strcpy), so NUL-bearing qwords cross the channel whole. The
small[8] frame puts the return slot at offset 16.

1. Read the served binary (<http://host:8000/orw-eval2>) and take the
   addresses of the .data anchors (`flag_path`, `out_buf`) and the
   gadgets (`pop_rdi_gadget`, `pop_rsi_gadget`, `pop_rdx_gadget`,
   `pop_rax_gadget`, `syscall_gadget`) with nm.
2. Build the chain: openat(AT_FDCWD=-100, flag_path, 0) ->
   read(fd=3, out_buf, 256) -> write(1, out_buf, 256) -> exit(0).
   The service closes fds 3..15 before installing the filter, so the
   openat lands on fd 3.
3. The service prints the flag.

## Flag

The chain opens `orw-eval2.flag` (relative to /opt/target).
