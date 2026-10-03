/* fmtstr target: printf(input) - the format IS the weapon. The fact
 * base decides: vuln=fmtstr -> fmtstr_write. A function pointer set
 * AFTER the printf: write its memory with %n, and win runs. The banner
 * announces the pointer's and win's addresses. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void win(void) {
    FILE *f = fopen("/opt/target/fmtstr.flag", "r");
    char flag[64];
    __asm__ volatile("and $-16, %rsp"); /* the smashed-frame alignment */
    if (!f) { puts("no flag file"); exit(1); }
    if (!fgets(flag, sizeof(flag), f)) exit(1);
    fputs("FLAG: ", stdout);
    fputs(flag, stdout);
    fflush(stdout);
    exit(0);
}

/* The call-through-pointer: NULL until someone writes it. */
void (*the_hook)(void) = NULL;

int main(void) {
    char input[256];
    ssize_t n;

    setvbuf(stdout, NULL, _IONBF, 0);
    char banner[128];
    snprintf(banner, sizeof(banner),
             "fmtstr target - hook() at %p win() at %p",
             (void *) &the_hook, (void *) &win);
    puts(banner);
    fputs("say? ", stdout);
    n = read(0, input, sizeof(input) - 1);
    if (n <= 0) return 1;
    input[n - 1] = 0;
    printf(input); /* the format string bug */
    fputs("\n", stdout);
    if (the_hook) the_hook(); /* written via %n: win() */
    return 0;
}
