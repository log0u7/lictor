/* ret2libc-002: the ret2libc WITHOUT a leak. The build is -static
 * + -no-pie: libc is baked in at fixed addresses, system and the
 * "/bin/sh" string both resolve statically (the chain is computed
 * offline from the binary, no leak round, no recon round trip). The
 * banner hands system's and the string's fixed addresses (what
 * offline recon would find); the craft is the chain, not the recon.
 * Compiled: -fno-stack-protector -no-pie -static. NX ON.
 *
 * The copy is bounded by the read length (memcpy, not strcpy): the
 * strike chain (pop rdi; the /bin/sh string; system) carries
 * NUL-bearing addresses - the read channel crosses them whole. The
 * 8-byte rsp shift gives the chain the ABI alignment system's SSE
 * prologue demands. Single-shot: the shell takes over from the
 * strike. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* the argument string: a .data resident, fixed address in the static
   build (the offline recon finds it next to system's address). */
char sh_cmd[] = "/bin/sh";

/* the gadget the chain needs: pop rdi; ret. NOINLINE + asm so it
   survives in .text at a known address. */
__attribute__((noinline)) void pop_rdi_gadget(void) {
    __asm__ volatile("pop %rdi; ret");
}

int vuln_copy(const char *src, size_t n) {
    /* 0x28, not 0x20: shifts this frame 8 bytes down, which makes
       rbp_v+8 (the return slot) 16-aligned, so a straight return into
       system enters with rsp % 16 == 8 - the ABI a real call would
       have left. With the 0x20 frame, do_system's SSE prologue faults
       on the misaligned stack. The small->ret distance is unchanged:
       the overflow geometry is identical. */
    char small[8];
    /* the read channel: bounded by n, not by a NUL - the chain
       crosses whole. */
    memcpy(small, src, n);
    return (int) n;
}

int main(void) {
    char input[512];
    ssize_t n;

    setvbuf(stdout, NULL, _IONBF, 0);
    /* the static build bakes the addresses in: the banner announces
       system, the /bin/sh string and the pop-rdi gadget. */
    char banner[160];
    snprintf(banner, sizeof(banner),
             "ret2libc-002 target - system() at %p sh() at %p gadget() at %p",
             (void *) &system, (void *) sh_cmd, (void *) &pop_rdi_gadget);
    puts(banner);
    fputs("name? ", stdout);
    n = read(0, input, sizeof(input) - 1);
    if (n <= 0) return 1;
    input[n - 1] = 0;
    /* the 8-byte rsp shift: the chain returns from vuln_copy into the
       pop-rdi gadget, which loads the /bin/sh string's address and
       falls into system at the ABI alignment. */
    __asm__ volatile("sub $8, %rsp");
    vuln_copy(input, (size_t) n);
    __asm__ volatile("add $8, %rsp");
    fputs("hello\n", stdout);
    return 0;
}
