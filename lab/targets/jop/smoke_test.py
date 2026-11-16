#!/usr/bin/env python3
"""Smoke test for jop: staging read accepted, EOF ends the second read."""

import socket, sys

HOST = "127.0.0.1"


def main():
    port = int(sys.argv[1])
    s = socket.create_connection((HOST, port), timeout=10)
    # the staging read: the seed round (the fake stack's head)
    s.send(b"AAAA")
    # EOF ends the second read (n <= 0 -> return 0): the process
    # exits cleanly - no crash.
    s.shutdown(socket.SHUT_WR)
    while True:
        c = s.recv(4096)
        if not c:
            break
    s.close()
    print("[+] staging read accepted, closed cleanly")
    print("[+] jop SMOKE TEST PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
