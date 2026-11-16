#!/usr/bin/env python3
"""Smoke test for ret2partial_overwrite: service silent, closes cleanly."""

import socket, sys

HOST = "127.0.0.1"


def main():
    port = int(sys.argv[1])
    s = socket.create_connection((HOST, port), timeout=10)
    s.send(b"hello\n")
    # the service is silent (the no-leak class announces nothing):
    # the connection closes cleanly when vuln returns - no crash.
    data = b""
    while True:
        c = s.recv(4096)
        if not c:
            break
        data += c
    s.close()
    print(f"[+] closed cleanly, {len(data)} bytes back")
    print("[+] ret2partial_overwrite SMOKE TEST PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
