/* callme_train: a TRAINING TWIN of the callme capability class (MR6).
 * Same skill (chain three gated foreign calls in order with the right
 * arguments), a different program: the VAULT - three lock stages
 * (vault_seal, vault_turn, vault_open), each gated by its OWN magic
 * triple (the emporium's callme arms everything with one shared
 * (0xdeadbeef, 0xcafebabe, 0xd00df00d) triple; here every stage
 * carries a distinct 0x51D1F0xx triple) and the chain must ride ONE
 * buffer overflow: the load3 gadget (pop rdi; pop rsi; pop rdx; ret)
 * fills the argument registers per stage, the stages gate on each
 * other (seal arms, turn confirms, open reads the flag). NO win()
 * shortcut: the stage sequence IS the win. The banner announces the
 * three stages, the gadget, probe(). Compiled: -fno-stack-protector
 * -no-pie, NX ON. The copy is bounded by the read length (memcpy):
 * the chain carries NUL-bearing qwords (the triples and the stage
 * addresses) - the read channel crosses them whole.
 *
 * The gadgets are TOP-LEVEL asm (bare symbols, no function prologue):
 * ret lands straight on the pops, toolchain-independent. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__asm__(
    ".text\n"
    ".globl load3_asm\n"
    ".type load3_asm, @function\n"
    "load3_asm:\n"
    "    pop %rdi\n"
    "    pop %rsi\n"
    "    pop %rdx\n"
    "    ret\n"
);
extern void load3_asm(void);

/* the measurement aid: a clean landing the pad calibration aims the
   return slot at (the echo decides the pad). */
void probe(void) {
    puts("probe: return landed");
    fflush(stdout);
    exit(0);
}

static int sealed = 0, turned = 0;

/* the three vault stages: each checks ITS OWN triple and only the
   correct order (seal, turn, open) opens the vault. */
void vault_seal(int a, int b, int c) {
    if (a == 0x51D1F001 && b == 0x51D1F002 && c == 0x51D1F003) {
        sealed = 1;
        puts("seal: OK");
    }
}

void vault_turn(int a, int b, int c) {
    if (sealed && a == 0x51D1F004 && b == 0x51D1F005 && c == 0x51D1F006) {
        turned = 1;
        puts("turn: OK");
    }
}

void vault_open(int a, int b, int c) {
    if (turned && a == 0x51D1F007 && b == 0x51D1F008 && c == 0x51D1F009) {
        FILE *f = fopen("callme_train.flag", "r");
        char flag[64];
        if (!f) { puts("no flag file"); exit(1); }
        if (!fgets(flag, sizeof(flag), f)) exit(1);
        fputs("FLAG: ", stdout);
        fputs(flag, stdout);
        fflush(stdout);
        exit(0);
    }
    puts("open: sequence wrong");
}

int vuln_copy(const char *src, size_t n) {
    /* the copy is bounded by the read length (memcpy, not strcpy):
       the chain carries NUL-bearing qwords - the read channel crosses
       them whole. */
    char small[8];
    memcpy(small, src, n);
    return (int) n;
}

int main(void) {
    char input[512];
    ssize_t n;

    setvbuf(stdout, NULL, _IONBF, 0);
    char banner[256];
    snprintf(banner, sizeof(banner),
             "callme_train target - seal() at %p turn() at %p open() at %p load3() at %p probe() at %p",
             (void *) &vault_seal, (void *) &vault_turn,
             (void *) &vault_open, (void *) &load3_asm, (void *) &probe);
    puts(banner);
    fputs("sequence? ", stdout);
    n = read(0, input, sizeof(input) - 1);
    if (n <= 0) return 1;
    input[n - 1] = 0;
    vuln_copy(input, (size_t) n);
    fputs("hello\n", stdout);
    return 0;
}
