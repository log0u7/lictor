#!/usr/bin/env python3
"""Smoke test for ret2vdso: echo oracle answers, leak rounds possible."""

import socket, sys

HOST = "127.0.0.1"


def recv_until(s, needle, limit=4096):
    data = b""
    while needle not in data and len(data) < limit:
        c = s.recv(4096)
        if not c:
            break
        data += c
    return data


def main():
    port = int(sys.argv[1])
    s = socket.create_connection((HOST, port), timeout=10)
    # the echo: send a plain string, expect it echoed back through puts
    s.send(b"smoke\n")
    data = recv_until(s, b"smoke\n")
    print(f"[+] echo: {data.decode(errors='replace').strip()[:80]}")
    assert b"smoke" in data, "the echo oracle did not answer"
    s.close()
    print("[+] ret2vdso SMOKE TEST PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
