#!/usr/bin/env python3
"""Smoke test for the 7 non-menu eval twins (fmtstr, orw, ret2plt,
ret2func, shellcode, ret2libc, callme, srop): the service answers,
the banner announces the addresses, the prompt is reachable.

The smoke test validates the DEPLOYMENT (the service answers, the
banner announces the addresses), not the exploit: the model-only
bench reads the vuln fact, the exploit runs in the lab exploit
phase.

Usage:
  python3 smoke_test.py <port> <banner_needle> <prompt_needle>

banner_needle is the banner substring the service prints (the
recon: the addresses or the gadget names).
prompt_needle is the prompt substring the service prints (the
read: the input the exploit lands the payload on).

The service answers, the banner announces the addresses: the
deployment is validated.
"""

import socket
import sys

HOST = "127.0.0.1"


def recv_until(s, needle, limit=4096):
    data = b""
    while needle not in data and len(data) < limit:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def main():
    port = int(sys.argv[1])
    banner_needle = sys.argv[2].encode()
    prompt_needle = sys.argv[3].encode()

    s = socket.create_connection((HOST, port), timeout=10)
    banner = recv_until(s, prompt_needle)
    print(f"[+] banner: {banner.decode(errors='replace').strip()}")
    assert banner_needle in banner, f"banner needle missing: {banner_needle!r}"
    assert prompt_needle in banner, f"prompt needle missing: {prompt_needle!r}"
    print("[+] SMOKE TEST PASSED (service answers, banner OK)")
    s.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
