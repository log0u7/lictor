/* ret2plt target: NO win() function. system@plt exists (a benign call
 * in main). The fact base decides: vuln=sof (strcpy), NX on, PIE off,
 * system imported -> ret2plt (call system directly: no leak needed).
 * The banner announces system@plt and an argument string's address. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char arg_cmd[] = "cat /opt/target/ret2plt.flag";

/* The gadget the demo needs: pop rdi; ret. Small binaries often lack
   it - the banner announces it (the "profiler findings" convenience).
   NOINLINE + asm so it survives in .text at a known address. */
__attribute__((noinline)) void pop_rdi_gadget(void) {
    __asm__ volatile("pop %rdi; ret");
}

int vuln_copy(const char *src, size_t n) {
    /* 0x28, not 0x20: shifts this frame 8 bytes down, which makes
       rbp_v+8 (the return slot) 16-aligned, so a straight return into
       system enters with rsp % 16 == 8 - the ABI a real call would
       have left. With the 0x20 frame, do_system's SSE prologue faults
       on the misaligned stack. The small->ret distance (16) is
       unchanged: the overflow geometry is identical. */
    char small[8];
    /* The read channel: the copy is bounded by n, not by a NUL, so
       NUL bytes ride and the textbook ret2plt chain (pop rdi; the
       command string; system) crosses whole. The unbounded copy into
       an 8-byte buffer is the entry point, same sof class. */
    memcpy(small, src, n);
    return (int) n;
}

int main(void) {
    char input[256];
    ssize_t n;

    setvbuf(stdout, NULL, _IONBF, 0);
    /* The useful addresses: system@plt (resolved), the command string,
       and the pop-rdi gadget. */
    char banner[160];
    snprintf(banner, sizeof(banner),
             "ret2plt target - system() at %p arg() at %p gadget() at %p",
             (void *) &system, (void *) arg_cmd, (void *) &pop_rdi_gadget);
    puts(banner);
    fputs("name? ", stdout);
    n = read(0, input, sizeof(input) - 1);
    if (n <= 0) return 1;
    input[n - 1] = 0;
    /* The 8-byte rsp shift: the ret2plt chain returns from vuln_copy
       into the pop-rdi gadget, which loads the command string's
       address and falls into system. system's entry needs
       rsp % 16 == 8 - the ABI alignment a call would have left - or
       do_system's SSE prologue faults on the misaligned stack. */
    __asm__ volatile("sub $8, %rsp");
    vuln_copy(input, (size_t) n);
    __asm__ volatile("add $8, %rsp");
    fputs("hello\n", stdout);
    return 0;
}
