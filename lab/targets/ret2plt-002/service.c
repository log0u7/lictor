/* ret2plt-002: the PLT-only target with full ASLR (PIE ON). NO
 * system, NO win: the flag rides in a heap buffer the service fills
 * at startup, its address parked in a global pointer. The exploit:
 * stage 1 - puts@plt prints the raw bytes at a .bss pointer (the heap
 * address rides out); stage 2 - write@plt dumps the buffer the pointer
 * names. Both stages ride the same overflow (the service loops); the
 * PIE anchor (main) and the gadgets are announced, the rest the
 * exploit derives from the leak. Compiled: -fno-stack-protector
 * -pie -fPIE, NX ON. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* the flag buffer: malloc'd at startup, its address parked in the
   global (the leak target: puts() prints the raw pointer bytes). */
static char *flag_ptr = NULL;

/* the gadget the chain needs: pop rdi; ret (stage 1 aims puts at the
   pointer's slot). */
__attribute__((noinline)) void pop_rdi_gadget(void) {
    __asm__ volatile("pop %rdi; ret");
}
/* stage 2's argument gadget: pop rsi; pop rdx; ret (the buffer
   address and the length). */
__attribute__((noinline)) void pop_rsi_rdx_gadget(void) {
    __asm__ volatile("pop %rsi; pop %rdx; ret");
}

int vuln_copy(const char *src, size_t n) {
    /* the copy is bounded by the read length (memcpy, not strcpy):
       the two-stage chain carries NUL-bearing addresses (the GOT and
       the heap buffer) - the read channel crosses them whole. The
       0x28 frame keeps the return slot 16-aligned so puts@plt's
       SSE prologue survives the straight return. */
    char small[8];
    memcpy(small, src, n);
    return (int) n;
}

int main(void) {
    char input[512];
    ssize_t n;

    setvbuf(stdout, NULL, _IONBF, 0);
    /* the flag rides in the heap from startup: the service opens the
       flag file into the buffer (the write stage's target). */
    FILE *f = fopen("ret2plt-002.flag", "r");
    if (!f) { puts("no flag file"); return 1; }
    flag_ptr = malloc(256);
    memset(flag_ptr, 0, 256);
    if (!fgets(flag_ptr, 255, f)) { puts("no flag"); return 1; }
    fclose(f);

    /* the PIE anchors: main and the gadgets (the exploit derives the
       rest from the leak + the offline offsets). */
    char banner[192];
    snprintf(banner, sizeof(banner),
             "ret2plt-002 target - main() at %p rdi() at %p rsi() at %p",
             (void *) &main, (void *) &pop_rdi_gadget,
             (void *) &pop_rsi_rdx_gadget);
    puts(banner);
    for (;;) {
        fputs("name? ", stdout);
        n = read(0, input, sizeof(input) - 1);
        if (n <= 0) return 1;
        input[n - 1] = 0;
        vuln_copy(input, (size_t) n);
        /* the ret2plt anchor: the service itself rides write@plt once
           (the exploit's stage-2 entry exists in the PLT because of
           this). */
        write(1, "hello\n", 6);
    }
}
