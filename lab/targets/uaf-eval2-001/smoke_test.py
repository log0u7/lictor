#!/usr/bin/env python3
"""Smoke test for uaf-eval2-001 (port 20000): service answers."""
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
    banner = recv_until(s, b"paint menu:")
    print(f"[+] banner: {banner.decode(errors='replace').strip()}")
    assert b"paint menu:" in banner
    s.send(b"x\n")
    s.close()
    print("[+] uaf-eval2-001 SMOKE TEST PASSED")
    return 0
if __name__ == "__main__":
    sys.exit(main())
