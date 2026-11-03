/* fmtstr-002: the format string on a PIE binary: LEAK first, WRITE
 * second. The banner hands nothing (PIE makes every address shift per
 * boot - the leak is the recon). The format walk reaches main's
 * anchor slot (a binary pointer parked on the stack): the leak round
 * prints it, the exploit derives the PIE base; the write round aims
 * %n at the hook pointer (PIE base + the offline offset) and win()
 * runs in the same round. Compiled: -fno-stack-protector -pie. NX ON.
 * The service loops: the leak round and the write round ride the same
 * format bug in one connection. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void win(void) {
    FILE *f = fopen("fmtstr-002.flag", "r");
    char flag[64];
    __asm__ volatile("and $-16, %rsp"); /* the smashed-frame alignment */
    if (!f) { puts("no flag file"); exit(1); }
    if (!fgets(flag, sizeof(flag), f)) exit(1);
    fputs("FLAG: ", stdout);
    fputs(flag, stdout);
    fflush(stdout);
    exit(0);
}

/* the write target: NULL until someone writes it. Its address lives
   in the PIE module (base + the offline offset). */
void (*the_hook)(void) = NULL;

int main(void) {
    char input[256];
    ssize_t n;
    /* the anchor: a binary pointer parked on the stack (volatile
       forces the slot) - the format walk reaches it, the leak round
       prints it, the PIE base falls out. */
    volatile void *anchor = &the_hook;

    setvbuf(stdout, NULL, _IONBF, 0);
    puts("fmtstr-002 target - leak first, write second: the format is the weapon");
    for (;;) {
        fputs("say? ", stdout);
        n = read(0, input, sizeof(input) - 1);
        if (n <= 0) return 1;
        input[n - 1] = 0;
        printf(input); /* the format string bug */
        fputs("\n", stdout);
        if (the_hook) the_hook(); /* written via %n: win() */
    }
}
