#!/usr/bin/env python3
"""Smoke test for got_partial_overwrite: format string echoes."""

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
    # the format string: %x echoes a stack word - the write primitive
    # answers on the same loop
    s.send(b"%x")
    data = recv_until(s, b"\n")
    print(f"[+] fmt echo: {data.decode(errors='replace').strip()[:80]}")
    assert data.strip(), "the format string did not echo"
    s.send(b"AAAA")
    data = recv_until(s, b"AAAA")
    assert b"AAAA" in data, "the loop did not echo the second round"
    # EOF ends the loop cleanly
    s.shutdown(socket.SHUT_WR)
    s.close()
    print("[+] got_partial_overwrite SMOKE TEST PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
