/* uaf_train_b: a TRAINING TWIN of the uaf_heap class (MR6), a
 * structurally different variant. Same capability (use-after-free on
 * a tcache chunk whose function pointer lives on the heap), a
 * different program: a TWO-SLOT registry indexed by number (the UAF
 * rides the INDEX, not a single pointer), a 32-byte record with the
 * handler at +24 (label first), a NUMBER menu with drop FIRST, and
 * the classic free-A / realloc-B / edit-via-stale-A flow: forge fills
 * the slots round-robin, drop frees WITHOUT clearing the slot, the
 * next forge re-mounts the freed chunk at the OTHER index, the patch
 * through the stale index lands on the live record, the invoke calls
 * it. PIE (the leak-and-strike twin): the banner carries win()'s
 * address, the forge echo leaks the chunk. Compiled:
 * -fno-stack-protector -pie -fPIE. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

void win(void) {
    __asm__ volatile("and $-16, %rsp");
    FILE *f = fopen("uaf_train_b.flag", "r");
    char flag[64];
    if (!f) { puts("no flag file"); exit(1); }
    if (!fgets(flag, sizeof(flag), f)) exit(1);
    fputs("FLAG: ", stdout);
    fputs(flag, stdout);
    fflush(stdout);
    exit(0);
}

static void noop(void) {
    puts("noop: the default handler");
}

struct record {
    char label[24];      /* the handler sits at +24: the tcache
                            metadata (next at 0, key at 8) never
                            reaches it */
    void (*handler)(void);
};

static struct record *slot[2] = { NULL, NULL };
static int cursor = 0;   /* the forge fills the slots round-robin */

static int read_index(int *out) {
    char line[8];
    if (!fgets(line, sizeof(line), stdin)) return 0;
    int i = atoi(line);
    if (i < 0 || i > 1) return 0;
    *out = i;
    return 1;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("registry ready. win() at %p\n", (void *) &win);
    puts("registry menu: 0=drop 1=forge 2=patch 3=invoke 4=bye");
    for (;;) {
        char line[16];
        if (!fgets(line, sizeof(line), stdin)) return 0;
        switch (line[0]) {
        case '0': {
            int i;
            if (!read_index(&i)) return 0;
            /* the UAF seed: the chunk is freed but the SLOT KEEPS it */
            if (slot[i]) {
                free(slot[i]);
                printf("drop: #%d released\n", i);
            }
            break;
        }
        case '1': {
            slot[cursor] = malloc(sizeof(struct record));
            slot[cursor]->handler = noop;
            printf("forge: #%d at %p handler=%p\n", cursor,
                   (void *) slot[cursor], (void *) slot[cursor]->handler);
            cursor = (cursor + 1) % 2;
            break;
        }
        case '2': {
            int i;
            if (!read_index(&i)) return 0;
            /* the UAF: the patch lands through the slot as it stands
               - stale (the freed chunk) or live (the re-mounted one):
               both are the same address once the tcache reuses */
            char value[24];
            if (!fgets(value, sizeof(value), stdin)) return 0;
            value[strcspn(value, "\n")] = 0;
            if (slot[i]) {
                slot[i]->handler = (void (*)(void)) strtoull(value, NULL, 16);
                printf("patch: #%d handler=%p\n", i, (void *) slot[i]->handler);
            }
            break;
        }
        case '3': {
            int i;
            if (!read_index(&i)) return 0;
            if (slot[i]) slot[i]->handler();
            printf("invoke: #%d done\n", i);
            break;
        }
        case '4':
            return 0;
        }
    }
}
