/* ret2libc-001: the classic ret2libc, PIE ON. The banner hands the
 * binary's own anchors (main, the vuln, the pop-rdi gadget - the PIE
 * base falls out of any of them); libc stays ASLR'd: the leak rides
 * puts(GOT) (the GOT entry's content prints as raw bytes), stage 2
 * aims system("/bin/sh") from the leaked libc base, and the shell cats
 * the flag. Compiled: -fno-stack-protector -pie. NX ON.
 *
 * The copy is bounded by the read length (memcpy, not strcpy): the
 * leak-bearing chain (pop rdi; the GOT slot; puts@plt; back to main)
 * and the strike chain (pop rdi; libc's /bin/sh; libc's system) carry
 * NUL-bearing addresses - the read channel crosses them whole. The
 * 8-byte rsp shift gives the chain the ABI alignment system's SSE
 * prologue demands. The service loops: the leak round and the strike
 * round ride the same overflow in one connection. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* the gadget the chains need: pop rdi; ret. NOINLINE + asm so it
   survives in .text at a known (PIE-shifted) address. */
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
    /* the read channel: the copy is bounded by n, not by a NUL, so
       NUL bytes ride and the two-stage chain crosses whole. */
    memcpy(small, src, n);
    return (int) n;
}

int main(void) {
    char input[512];
    ssize_t n;

    setvbuf(stdout, NULL, _IONBF, 0);
    /* The PIE anchors: main, the vuln, the gadget (any one of them
       yields the PIE base; libc is NOT announced - the leak rides
       puts(GOT)). */
    char banner[160];
    snprintf(banner, sizeof(banner),
             "ret2libc-001 target - main() at %p vuln() at %p gadget() at %p",
             (void *) &main, (void *) &vuln_copy, (void *) &pop_rdi_gadget);
    puts(banner);
    for (;;) {
        fputs("name? ", stdout);
        n = read(0, input, sizeof(input) - 1);
        if (n <= 0) return 1;
        input[n - 1] = 0;
        /* the 8-byte rsp shift: the chain returns from vuln_copy into
           the pop-rdi gadget, which loads the next slot and falls into
           the next chain entry - puts@plt (the leak round) or system
           (the strike round) - both entering at the ABI alignment. */
        __asm__ volatile("sub $8, %rsp");
        vuln_copy(input, (size_t) n);
        __asm__ volatile("add $8, %rsp");
        fputs("hello\n", stdout);
    }
}
