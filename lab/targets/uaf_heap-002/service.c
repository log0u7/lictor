/* uaf_heap-002: the UAF behind a SAFE-LINKED tcache. Compiled against
 * bookworm glibc 2.36 (tcache present, safe-linking on): after the
 * free, the chunk's first word is the tcache next pointer MANGLED
 * (PROTECT_PTR: (pos >> 12) ^ ptr) - a naive read sees garbage, a
 * naive poison lands nowhere. The menu's edit writes the fn slot
 * straight through the dangling pointer (the UAF): the exploit aims it
 * at win() and the call - which only fires through a FREED chunk -
 * runs. The mangling only matters to whoever tries the poisoned path.
 * No banner addresses (no-PIE: the facts come from the binary): the
 * alloc leak prints the chunk address (the mangling's pos).
 * Compiled: -fno-stack-protector -no-pie (the stack stays boring; the
 * heap is the weapon). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

void win(void) {
    __asm__ volatile("and $-16, %rsp");
    FILE *f = fopen("uaf_heap-002.flag", "r");
    char flag[64];
    if (!f) { puts("no flag file"); exit(1); }
    if (!fgets(flag, sizeof(flag), f)) exit(1);
    fputs("FLAG: ", stdout);
    fputs(flag, stdout);
    fflush(stdout);
    exit(0);
}

struct obj {
    void (*fn)(void);
    char name[8];
};

static struct obj *held = NULL;
static int freed = 0; /* the call fires only through the FREED chunk */

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("heap menu: 1=alloc 2=free 3=edit 4=call 5=quit");
    for (;;) {
        char line[16];
        if (!fgets(line, sizeof(line), stdin)) return 0;
        switch (line[0]) {
        case '1': {
            held = malloc(sizeof(struct obj));
            held->fn = NULL;
            memset(held->name, 0, sizeof(held->name));
            freed = 0;
            printf("alloc: %p\n", (void *) held);
            break;
        }
        case '2':
            if (held) {
                /* the chunk lands in the tcache: the fn slot becomes
                   the safe-linked next pointer, the name slot becomes
                   the tcache key (double-free detection reads it) */
                free(held);
                freed = 1;
                puts("free: done (safe-linked)");
            }
            break;
        case '3': {
            /* the UAF: the freed chunk is still referenced AND
               writable. The edit lands on the fn slot = the mangled
               next pointer: the exploit writes the raw target through
               the dangling pointer (the mangling is the trap the
               poisoned path falls into). */
            char value[16];
            if (!fgets(value, sizeof(value), stdin)) return 0;
            value[strcspn(value, "\n")] = 0;
            held->fn = (void (*)(void)) strtoull(value, NULL, 16);
            printf("edit: %p <- fn=%p\n", (void *) held, (void *) held->fn);
            break;
        }
        case '4':
            /* the call fires only through the FREED chunk: the UAF's
               trigger (an alloc'd chunk would fail the check) */
            if (held && freed) held->fn();
            puts("called");
            break;
        case '5':
            return 0;
        }
    }
}
