/* ret2vdso: the vDSO class. PIE, no canary, NX on - and the main
 * binary has NO syscall gadget of its own: the only syscall-bearing
 * page is the vDSO, mapped by the loader itself. The exploit leaks
 * libc (puts(GOT[puts])), walks the stack to the auxv
 * (AT_SYSINFO_EHDR = the vDSO base), hunts the vDSO's `syscall; ret`
 * through the leak rounds, then strikes: execve("/bin/sh", NULL,
 * NULL) with rax=59 from the pop rax gadget and the vDSO's syscall.
 * The echo `puts(buf)` is the leak oracle. Compiled: -fno-stack-
 * protector -pie -fPIE, NX ON. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__asm__(
    ".text\n"
    ".globl pop3_asm\n"
    "pop3_asm:\n"
    "    pop %rdi\n"
    "    pop %rsi\n"
    "    pop %rdx\n"
    "    ret\n"
    ".globl pop_rax_asm\n"
    "pop_rax_asm:\n"
    "    pop %rax\n"
    "    ret\n"
);
extern void pop3_asm(void), pop_rax_asm(void);

int vuln(void) {
    char buf[64];
    /* the copy is bounded by the read length (memcpy, not strcpy):
       the chain qwords cross the channel whole. */
    memset(buf, 0, sizeof buf);
    ssize_t n = read(0, buf, 256);
    if (n <= 0) return 0;
    /* the echo: the leak oracle (return to puts with a controlled
       rdi - the raw bytes of any address ride out). */
    puts(buf);
    fflush(stdout);
    return (int) n;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
