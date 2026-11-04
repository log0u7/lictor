/* ret2libc_train: a TRAINING TWIN of the ret2libc capability class
 * (MR6). Same skill (leak a libc pointer, derive the base, strike
 * system("/bin/sh")), a different program: ret2libc-001 is PIE and
 * leaks GOT[read] through a looping prompt; this twin is no-PIE,
 * single-loop, and leaks the puts GOT slot THROUGH puts itself - the
 * banner announces the static anchors (the pop-rdi gadget, a bare ret
 * for the alignment leg, the binary's own "/bin/sh" string, probe())
 * - everything but libc is fixed. The leak round: chain =
 * pop_rdi; &GOT[puts]; puts@plt; back to main - puts prints the raw
 * libc pointer, main re-prompts. The strike round: chain = pop_rdi;
 * "/bin/sh"; ret; system - libc's system from the leaked base runs
 * the shell, the shell cats the flag. Compiled: -fno-stack-protector
 * -no-pie, NX ON. The copy is bounded by the read length (memcpy):
 * both chains carry NUL-bearing addresses.
 *
 * The gadgets are TOP-LEVEL asm symbols (no prologue): ret lands
 * straight on the pops, toolchain-independent. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__asm__(
    ".text\n"
    ".globl pop_rdi_asm\n"
    ".type pop_rdi_asm, @function\n"
    "pop_rdi_asm:\n"
    "    pop %rdi\n"
    "    ret\n"
    ".globl ret_asm\n"
    ".type ret_asm, @function\n"
    "ret_asm:\n"
    "    ret\n"
);
extern void pop_rdi_asm(void);
extern void ret_asm(void);

/* the binary's own argument string (no libc string hunt needed) */
static const char sh_arg[] = "/bin/sh";

/* the measurement aid: a clean landing the pad calibration aims the
   return slot at (the echo decides the pad). */
void probe(void) {
    puts("probe: return landed");
    fflush(stdout);
    exit(0);
}

int vuln_copy(const char *src, size_t n) {
    /* the copy is bounded by n, not a NUL: both chains carry
       NUL-bearing addresses - the read channel crosses them whole. */
    char small[8];
    memcpy(small, src, n);
    return (int) n;
}

int main(void) {
    char input[512];
    ssize_t n;

    setvbuf(stdout, NULL, _IONBF, 0);
    /* the static anchors (no-PIE: fixed per binary): the gadget, the
       alignment leg, the "/bin/sh" string, probe, main. libc stays
       hidden - the leak rides puts(GOT[puts]). */
    printf("ret2libc_train target - pop_rdi() at %p ret() at %p sh() at %p probe() at %p main() at %p\n",
           (void *) &pop_rdi_asm, (void *) &ret_asm, (void *) sh_arg,
           (void *) &probe, (void *) &main);
    for (;;) {
        fputs("name? ", stdout);
        n = read(0, input, sizeof(input) - 1);
        if (n <= 0) return 1;
        input[n - 1] = 0;
        vuln_copy(input, (size_t) n);
        fputs("hello\n", stdout);
    }
}
