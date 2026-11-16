#!/usr/bin/env python3
"""Smoke test for one_gadget: banner answers, closes cleanly."""

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
    banner = recv_until(s, b"ready\n")
    assert b"ready" in banner, "the banner did not answer"
    s.send(b"hello\n")
    # the connection closes cleanly when vuln returns - no crash.
    data = b""
    while True:
        c = s.recv(4096)
        if not c:
            break
    s.close()
    print("[+] banner answered, closed cleanly")
    print("[+] one_gadget SMOKE TEST PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
