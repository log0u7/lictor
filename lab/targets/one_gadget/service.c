/* one_gadget: the single-qword class. Dynamic libc, no PIE, no
 * canary, NX on. ONE buffer overflow, ONE qword: the leaked
 * one_gadget address lands on the return slot - no chain, no
 * /bin/sh string hunt. The exploit leaks libc via puts(GOT[puts])
 * (pop_rdi_asm), picks the one_gadget (execve("/bin/sh", ...) with
 * its constraint), and lands it on the return slot. The constraint:
 * the one_gadget wants the stack BEHIND the return slot zeroed - the
 * read channel lets the exploit park zeros there (memcpy, not
 * strcpy, crosses NULs whole). Compiled: -fno-stack-protector
 * -no-pie, NX ON. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__asm__(
    ".text\n"
    ".globl pop_rdi_asm\n"
    "pop_rdi_asm:\n"
    "    pop %rdi\n"
    "    ret\n"
);
extern void pop_rdi_asm(void);

int vuln(void) {
    char buf[64];
    /* the copy is bounded by the read length (memcpy, not strcpy):
       the one_gadget qword and the trailing zero park cross the
       channel whole. */
    memset(buf, 0, sizeof buf);
    ssize_t n = read(0, buf, 256);
    if (n <= 0) return 0;
    return (int) n;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    /* the banner: imports puts@plt (the leak round's anchor) and
       announces nothing about the win */
    puts("ready");
    vuln();
    return 0;
}
