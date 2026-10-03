/* shellcode target: NX OFF (compiled with -z execstack). NO win().
 * The fact base decides: vuln=sof, NX off, no canary -> shellcode
 * (the input is reachable and executable). The banner announces the
 * input buffer's address (where the payload lands, on the stack). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int vuln_copy(const char *src) {
    char small[8];
    strcpy(small, src); /* the write-up classic: unbounded */
    return (int) strlen(small);
}

int main(void) {
    char input[256];
    ssize_t n;

    setvbuf(stdout, NULL, _IONBF, 0);
    /* input[] is where the payload lives (main's frame, on the
       executable stack): returning into it runs the shellcode. */
    char banner[96];
    snprintf(banner, sizeof(banner),
             "shellcode target - buf() at %p", (void *) input);
    puts(banner);
    fputs("name? ", stdout);
    n = read(0, input, sizeof(input) - 1);
    if (n <= 0) return 1;
    input[n - 1] = 0;
    vuln_copy(input);
    fputs("hello\n", stdout);
    return 0;
}
