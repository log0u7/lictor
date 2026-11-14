#!/usr/bin/env python3
"""Smoke test for ret2libc-eval2: service answers."""
import socket, sys
HOST = "127.0.0.1"
def recv_until(s, needle, limit=4096):
    data = b""
    while needle not in data and len(data) < limit:
        c = s.recv(4096)
        if not c: break
        data += c
    return data
def main():
    port = int(sys.argv[1])
    s = socket.create_connection((HOST, port), timeout=10)
    banner = recv_until(s, b"name? ")
    print(f"[+] banner: {banner.decode(errors='replace').strip()}")
    assert b"name? ".strip() in banner or b"name?" in banner
    s.send(b"hello\n")
    s.close()
    print("[+] ret2libc-eval2 SMOKE TEST PASSED")
    return 0
if __name__ == "__main__":
    sys.exit(main())
