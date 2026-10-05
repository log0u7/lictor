/* The heap target: a UAF the tcache handout makes trivial. Compiled
 * against bookworm glibc 2.36 (tcache present, minor 36). No banner
 * addresses, no win in the banner: the facts come from the source
 * knowledge (the suggest flow), not from the profiler alone.
 *
 * The object carries a function pointer ON THE HEAP: free it (the
 * chunk lands in the tcache), allocate it again (tcache reuse - same
 * address), edit the pointer, call it: the UAF-to-win in one menu.
 * Compiled: -fno-stack-protector -no-pie (the stack stays boring; the
 * heap is the weapon). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void win(void) {
    __asm__ volatile("and $-16, %rsp");
    FILE *f = fopen("uaf_heap.flag", "r");
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
            printf("alloc: %p\n", (void *) held);
            break;
        }
        case '2':
            if (held) { free(held); puts("free: done (the pointer stayed)"); }
            break;
        case '3': {
            /* the UAF: the freed chunk is still referenced AND writable */
            char value[16];
            if (!fgets(value, sizeof(value), stdin)) return 0;
            value[strcspn(value, "\n")] = 0;
            memcpy(held->name, value, sizeof(held->name));
            printf("edit: %p <- %s\n", (void *) held, held->name);
            break;
        }
        case '4':
            if (held) held->fn(); /* the call through the (maybe freed) chunk */
            puts("called");
            break;
        case '5':
            return 0;
        }
    }
}
