/* ret2partial_overwrite: the NO-LEAK fallback class. Static PIE
 * binary (no libc, no PLT, no leak primitives), no canary, NX on.
 * PIE randomizes pages, not the low 12 bits: overwrite ONLY the
 * low 2 bytes of the saved return address to hop onto win() - the
 * exploit probes the page hop (up to 16 tries on the 4 random
 * bits), no leak needed. The copy is bounded by the read length
 * (memcpy, not strcpy): the 2-byte partial rides the channel whole
 * and the high 6 bytes of the saved RIP stay original. Compiled:
 * -fno-stack-protector -static-pie, NX ON. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

void win(void) {
    /* the flag door: the page hop lands here */
    int fd = open("/opt/target/ret2partial_overwrite.flag", O_RDONLY);
    char line[128];
    if (fd >= 0) {
        ssize_t n = read(fd, line, sizeof line);
        if (n > 0) write(1, line, n);
        close(fd);
    }
    _exit(0);
}

int vuln(void) {
    char buf[64];
    /* the copy is bounded by the read length (memcpy, not strcpy):
       the 2-byte partial rides the channel whole. */
    memset(buf, 0, sizeof buf);
    ssize_t n = read(0, buf, 256);
    if (n <= 0) return 0;
    return (int) n;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
