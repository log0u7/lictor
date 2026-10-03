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

int vuln_copy(const char *src) {
    char small[8];
    strcpy(small, src); /* the write-up classic: unbounded */
    return (int) strlen(small);
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
    vuln_copy(input);
    fputs("hello\n", stdout);
    return 0;
}
