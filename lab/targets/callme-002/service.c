/* callme-002: the call-me convention, the 3-argument variant. THREE
 * helper functions must fire in the correct order (one, two, three),
 * each with the (1,2,3) argument triple (pop rdi; pop rsi; pop rdx;
 * ret populates the registers per helper). The helpers gate on each
 * other - one arms the sequence, two confirms it, three reads the
 * flag. NO win() shortcut: the helper sequence IS the win. The banner
 * announces the three helpers and the pop3 gadget. The copy is bounded
 * by the read length (memcpy): the chain carries NUL-bearing values
 * (1, 2, 3 as qwords) and the helper addresses. Compiled:
 * -fno-stack-protector -no-pie, NX ON. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* the gadget the chain needs: pop rdi; pop rsi; pop rdx; ret. The
   emporium's original calls for it - here it is explicit (NOINLINE +
   asm so it survives in .text at a known address). */
__attribute__((noinline)) void pop3_gadget(void) {
    __asm__ volatile("pop %rdi; pop %rsi; pop %rdx; ret");
}

static int done1 = 0, done2 = 0;

/* the three helpers: each checks its three arguments and only the
   correct sequence (one, two, three) opens the flag. */
void helper_one(int a, int b, int c) {
    if (a == 1 && b == 2 && c == 3) { done1 = 1; puts("one: OK"); }
}

void helper_two(int a, int b, int c) {
    if (done1 && a == 1 && b == 2 && c == 3) { done2 = 1; puts("two: OK"); }
}

void helper_three(int a, int b, int c) {
    if (done2 && a == 1 && b == 2 && c == 3) {
        FILE *f = fopen("callme-002.flag", "r");
        char flag[64];
        if (!f) { puts("no flag file"); exit(1); }
        if (!fgets(flag, sizeof(flag), f)) exit(1);
        fputs("FLAG: ", stdout);
        fputs(flag, stdout);
        fflush(stdout);
        exit(0);
    }
    puts("three: sequence wrong");
}

int vuln_copy(const char *src, size_t n) {
    /* the copy is bounded by the read length (memcpy, not strcpy):
       the chain carries NUL-bearing values (1, 2, 3 as qwords) and
       the helper addresses - the read channel crosses them whole. */
    char small[8];
    memcpy(small, src, n);
    return (int) n;
}

int main(void) {
    char input[512];
    ssize_t n;

    setvbuf(stdout, NULL, _IONBF, 0);
    char banner[224];
    snprintf(banner, sizeof(banner),
             "callme-002 target - one() at %p two() at %p three() at %p gadget() at %p",
             (void *) &helper_one, (void *) &helper_two,
             (void *) &helper_three, (void *) &pop3_gadget);
    puts(banner);
    fputs("name? ", stdout);
    n = read(0, input, sizeof(input) - 1);
    if (n <= 0) return 1;
    input[n - 1] = 0;
    vuln_copy(input, (size_t) n);
    fputs("hello\n", stdout);
    return 0;
}
