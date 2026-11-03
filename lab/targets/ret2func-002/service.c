/* ret2func-002: the stack overflow BEHIND a canary. Compiled WITH
 * -fstack-protector-strong (the canary sits above the buffer), -no-pie.
 * The leak is built in: the copy DUMPS 40 raw bytes from the buffer
 * (write(1, ...), not puts - the NUL-bearing canary rides out whole),
 * the strike round restores the leaked canary verbatim and aims
 * win(). The banner announces win() (the target). The service loops:
 * the leak round and the strike round ride the same overflow in one
 * connection. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void win(void) {
    /* The smashed saved-rbp leaves rsp misaligned when the ret lands
       here; the inner puts demands a 16-byte-aligned rsp. Realigned
       right after the prologue (locals stay rbp-relative). */
    __asm__ volatile("and $-16, %rsp");
    FILE *f = fopen("ret2func-002.flag", "r");
    char flag[64];
    if (!f) { puts("no flag file"); exit(1); }
    if (!fgets(flag, sizeof(flag), f)) exit(1);
    fputs("FLAG: ", stdout);
    fputs(flag, stdout);
    fflush(stdout);
    exit(0);
}

int vuln_copy(const char *src, size_t n) {
    /* the copy is bounded by the read length (memcpy, not strcpy):
       the strike payload carries the canary's own NUL byte and the
       win() address's NULs - the read channel crosses them whole. */
    char small[8];
    memcpy(small, src, n);
    /* the dump: 40 raw bytes ride out - the canary (above the
       buffer), the saved rbp and the return slot sit in there. The
       glibc canary's first byte is NUL: puts would stop short, write
       crosses whole. */
    write(1, small, 40);
    return (int) n;
}

int main(void) {
    char input[512];
    ssize_t n;

    setvbuf(stdout, NULL, _IONBF, 0);
    char banner[128];
    snprintf(banner, sizeof(banner),
             "ret2func-002 target - win() at %p", (void *) &win);
    puts(banner);
    for (;;) {
        fputs("name? ", stdout);
        n = read(0, input, sizeof(input) - 1);
        if (n <= 0) return 1;
        input[n - 1] = 0;
        vuln_copy(input, (size_t) n);
        fputs("hello\n", stdout);
    }
}
