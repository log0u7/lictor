/* shellcode-002: NX OFF (-z execstack), PIE ON. The shellcode rides
 * the stack; with PIE the buffer's address shifts per boot - the
 * banner's buf leak is LOAD-BEARING (the return address aims the leaked
 * buf). NO win(): the payload IS the answer (execve("/bin/sh"), the
 * shell cats the flag). Compiled: -fno-stack-protector -pie
 * -z execstack. Single-shot: the shell takes over from the payload.
 * Distinct from shellcode (no-PIE, the buf address is fixed): here
 * the exploit must consume the leak in the same connection. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int vuln_copy(const char *src) {
    char small[8];
    strcpy(small, src); /* the write-up classic: unbounded, NUL-terminated */
    return (int) strlen(small);
}

int main(void) {
    char input[256];
    ssize_t n;

    setvbuf(stdout, NULL, _IONBF, 0);
    /* input[] is where the payload lives (main's frame, on the
       executable stack): returning into it runs the shellcode. With
       PIE the address shifts per boot - the leak is the exploit's
       anchor. */
    char banner[128];
    snprintf(banner, sizeof(banner),
             "shellcode-002 target - buf() at %p (PIE: the leak is the anchor)",
             (void *) input);
    puts(banner);
    fputs("name? ", stdout);
    n = read(0, input, sizeof(input) - 1);
    if (n <= 0) return 1;
    input[n - 1] = 0;
    vuln_copy(input);
    fputs("hello\n", stdout);
    return 0;
}
