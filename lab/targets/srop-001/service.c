/* srop-001: Sigreturn Oriented Programming. The binary carries a
 * sigreturn gadget (mov rax, 15; syscall) - the banner announces it
 * and the "/bin/sh" string beside it. The exploit crafts an
 * rt_sigreturn frame on the stack: ret into the gadget, rax=15, and
 * the kernel restores the WHOLE register state from the frame -
 * execve("/bin/sh", NULL, NULL) in one pivot, the shell cats the
 * flag. Compiled: -fno-stack-protector -no-pie, NX ON (the frame is
 * data, not code: execstack unnecessary). The copy is bounded by the
 * read length (memcpy): the sigreturn frame carries NUL bytes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* the argument string the frame's execve needs */
static char sh_cmd[] = "/bin/sh";

/* the gadget the exploit needs: mov rax, 15; syscall (the sigreturn
   pivot). NOINLINE + asm so it survives in .text at a known address -
   the banner announces it. */
__attribute__((noinline)) void sigreturn_gadget(void) {
    __asm__ volatile("mov $15, %rax; syscall");
}

int vuln_copy(const char *src, size_t n) {
    /* the copy is bounded by the read length (memcpy, not strcpy):
       the sigreturn frame carries NUL bytes (the zeroed registers),
       the read channel crosses it whole. */
    char small[8];
    memcpy(small, src, n);
    return (int) n;
}

int main(void) {
    char input[512];
    ssize_t n;

    setvbuf(stdout, NULL, _IONBF, 0);
    /* the exploit needs two addresses: the gadget (the pivot) and the
       argument string (the frame's execve rdi). */
    char banner[128];
    snprintf(banner, sizeof(banner),
             "srop-001 target - gadget() at %p sh() at %p",
             (void *) &sigreturn_gadget, (void *) sh_cmd);
    puts(banner);
    fputs("name? ", stdout);
    n = read(0, input, sizeof(input) - 1);
    if (n <= 0) return 1;
    input[n - 1] = 0;
    vuln_copy(input, (size_t) n);
    fputs("hello\n", stdout);
    return 0;
}
