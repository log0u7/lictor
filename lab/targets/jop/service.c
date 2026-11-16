/* jop: the JOP (Jump-Oriented Programming) class. NX on, no PIE,
 * no canary. The pivot: the indirect transfer rides a REGISTER, not
 * the stack - the vuln's return value lands in rax, the pivot
 * gadget `xchg rsp, rax; ret` consumes it. The exploit stages the
 * fake stack in .bss (dispatcher_target) with a first read, then
 * overflows: the return slot takes the pivot gadget, the seed qword
 * (the slot behind the return slot) takes the fake-stack address and
 * lands in rax. The pivot lands rsp on the fake stack (seeded high,
 * slack below it: win's own frames run inside the .bss buffer). Compiled:
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
    ".globl pivot_asm\n"
    "pivot_asm:\n"
    "    xchg %rsp, %rax\n"
    "    ret\n"
);
extern void pivot_asm(void);
extern void pop_rdi_asm(void);

/* the fake stack: the pivot lands rsp here. The exploit stages the
 * win address at the LAST qword (offset 4096): the stack grows DOWN
 * from the seed, so the slack below it hosts win's own frames. */
char dispatcher_target[4104];

void win(void) {
    /* the flag door: the staged fake stack hosts win's frames */
    FILE *f = fopen("/opt/target/jop.flag", "r");
    char line[128];
    if (f) {
        while (fgets(line, sizeof line, f)) fputs(line, stdout);
        fclose(f);
    }
    fflush(stdout);
    _exit(0);
}

size_t vuln(void) {
    char buf[64];
    memset(buf, 0, sizeof buf);
    /* stage 1: the staging read - the seed lands in .bss (no stack
       overflow: the staging buffer IS the fake stack). */
    ssize_t n = read(0, dispatcher_target, 8192);
    if (n <= 0) return 0;
    memset(buf, 0, sizeof buf);
    /* stage 2: the overflow - the return slot takes the pivot
       gadget, the seed qword (the slot behind the return slot) takes the
       fake-stack address and lands in rax. */
    ssize_t m = read(0, buf, 256);
    if (m <= 0) return 0;
    /* the register control: the payload's seed qword (buf+96, the
       slot behind the return slot) lands in rax - the pivot gadget
       consumes it. */
    return *(size_t *)(buf + 96);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
