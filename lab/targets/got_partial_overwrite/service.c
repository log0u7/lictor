/* got_partial_overwrite: the GOT-hijack class. Partial RELRO (the
 * default gcc layout: GOT writable), no PIE, no canary, NX on. The
 * service loops: read a line, printf it - the format string IS the
 * write primitive. The exploit overwrites ONLY the low bytes of
 * GOT[printf] so the imported function lands on win() (no leak
 * needed: no PIE keeps the GOT page fixed). The next loop
 * iteration calls win through the hijacked GOT entry. Compiled:
 * -fno-stack-protector -no-pie -O0 (default RELRO = partial). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void win(void) {
    /* the flag door: the hijacked GOT entry lands here */
    FILE *f = fopen("/opt/target/got_partial_overwrite.flag", "r");
    char line[128];
    if (f) {
        while (fgets(line, sizeof line, f)) fputs(line, stdout);
        fclose(f);
    }
    fflush(stdout);
    _exit(0);
}

int vuln(void) {
    char buf[128];
    memset(buf, 0, sizeof buf);
    ssize_t n = read(0, buf, 200);
    if (n <= 0) return -1;
    /* the format string IS the write primitive: %n writes where
     * the exploit points. The loop gives the write a second call
     * to land on. */
    printf(buf);
    printf("\n");
    fflush(stdout);
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    while (vuln() == 0) {
        /* the loop: the write stage lands on the NEXT printf call */
    }
    return 0;
}
