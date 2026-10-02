/* The demo target: banner announces win(); an unbounded copy follows.
 * Compiled: -fno-stack-protector -no-pie. NX stays ON.
 * Output via puts/fputs (printf with a controlled format would be a
 * DIFFERENT technique - the demo isolates the stack overflow). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void win(void) {
    /* The smashed saved-rbp leaves rsp misaligned when the ret lands
       here; the inner puts demands a 16-byte-aligned rsp. Realigned
       right after the prologue (locals stay rbp-relative). */
    __asm__ volatile("and $-16, %rsp");
    FILE *f = fopen("flag.txt", "r");
    char flag[64];
    if (!f) { puts("no flag file"); exit(1); }
    if (!fgets(flag, sizeof(flag), f)) exit(1);
    fputs("FLAG: ", stdout);
    fputs(flag, stdout);
    fflush(stdout);
    exit(0);
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
    /* The banner announces BOTH addresses: the exploit realigns the
       stack with the ret gadget before jumping to win (the inner puts
       needs a 16-byte aligned rsp - the smashed rbp misaligns it).
       0x40127f = the ret instruction at the end of vuln_copy. */
    char banner[128];
    snprintf(banner, sizeof(banner),
             "augure demo target - win() at %p ret() at %p",
             (void *) &win, (void *) 0x40127f);
    puts(banner);
    fputs("name? ", stdout);
    n = read(0, input, sizeof(input) - 1);
    if (n <= 0) return 1;
    input[n - 1] = 0; /* strip the newline */
    vuln_copy(input);
    fputs("hello\n", stdout);
    return 0;
}
