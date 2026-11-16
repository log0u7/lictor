/* setcontext_srop: the sigreturn class. Dynamic libc, no PIE, no
 * canary, NX on. The sigreturn path has two doors: the classic SROP
 * frame and the setcontext gadget. Here the exploit rides the
 * CLASSIC door: pop rax=15, a libc `syscall; ret` gadget, then the
 * forged sigreturn frame rides the payload itself - rdi="/bin/sh",
 * rip=system, rsp=staging (.bss). The exploit leaks libc via
 * puts(GOT[puts]) (pop_rdi_asm), then lands the frame. Compiled:
 * -fno-stack-protector -no-pie, NX ON. */
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
    ".globl pop_rax_asm\n"
    "pop_rax_asm:\n"
    "    pop %rax\n"
    "    ret\n"
    ".globl syscall_ret_asm\n"
    "syscall_ret_asm:\n"
    "    syscall\n"
    "    ret\n"
    ".globl sigreturn_asm\n"
    "sigreturn_asm:\n"
    "    mov $15, %rax\n"
    "    syscall\n"
);
extern void pop_rdi_asm(void);
extern void pop_rax_asm(void);
extern void syscall_ret_asm(void);
extern void sigreturn_asm(void);

/* the fake stack: the forged frame's rsp lands here (system's own
   stack usage runs inside it) */
char staging[4096];

int vuln(void) {
    char buf[64];
    /* the copy is bounded by the read length (memcpy semantics):
       the NUL-bearing frame qwords cross the channel whole. */
    memset(buf, 0, sizeof buf);
    ssize_t n = read(0, buf, 512);
    if (n <= 0) return 0;
    return (int) n;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    /* the banner: the only output, announces nothing */
    puts("ready");
    vuln();
    return 0;
}
