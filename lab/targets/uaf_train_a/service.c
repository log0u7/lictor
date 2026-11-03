/* uaf_train_a: a TRAINING TWIN of the uaf_heap class (MR6). Same
 * capability (use-after-free on a tcache chunk whose function pointer
 * lives on the heap), a different program: 48-byte canvas struct with
 * the brush pointer at +40 (past the tcache next AND key), a LETTER
 * menu ([f]ree listed first), and a live-check on the call: `go`
 * refuses a freed chunk, so the free forces the tcache-REUSE path (a
 * fresh new() re-mounts the same chunk before the paint can win).
 * Compiled: -fno-stack-protector -no-pie (the stack stays boring; the
 * heap is the weapon). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

void win(void) {
    __asm__ volatile("and $-16, %rsp");
    FILE *f = fopen("uaf_train_a.flag", "r");
    char flag[64];
    if (!f) { puts("no flag file"); exit(1); }
    if (!fgets(flag, sizeof(flag), f)) exit(1);
    fputs("FLAG: ", stdout);
    fputs(flag, stdout);
    fflush(stdout);
    exit(0);
}

struct canvas {
    char title[40];      /* the brush pointer sits at +40: the tcache
                            metadata (next at 0, key at 8) never
                            reaches it */
    void (*brush)(void);
};

static struct canvas *easel = NULL;
static int mounted = 0; /* go fires only through a LIVE chunk: after
                           the free, a fresh new() must re-mount the
                           tcache-reused chunk before the paint wins */

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("paint menu: [f]ree [n]ew [p]aint [g]o [x]it");
    for (;;) {
        char line[16];
        if (!fgets(line, sizeof(line), stdin)) return 0;
        switch (line[0]) {
        case 'n': {
            easel = malloc(sizeof(struct canvas));
            easel->brush = NULL;
            mounted = 1;
            printf("new: canvas at %p (mounted)\n", (void *) easel);
            break;
        }
        case 'f':
            if (easel) {
                free(easel);
                mounted = 0;
                puts("free: canvas released (tcache holds it)");
            }
            break;
        case 'p': {
            /* the UAF: after the free the chunk is still referenced
               AND writable; after the re-mount `easel` is the SAME
               address the tcache handed back (the reuse). Either way
               the paint writes the brush slot straight. */
            char value[24];
            if (!fgets(value, sizeof(value), stdin)) return 0;
            value[strcspn(value, "\n")] = 0;
            easel->brush = (void (*)(void)) strtoull(value, NULL, 16);
            printf("paint: brush <- %p\n", (void *) easel->brush);
            break;
        }
        case 'g':
            /* the live-check: a freed chunk refuses to fire - the
               exploit MUST take the reuse path (new after free) */
            if (easel && mounted) easel->brush();
            puts("go: stroke done");
            break;
        case 'x':
            return 0;
        }
    }
}
