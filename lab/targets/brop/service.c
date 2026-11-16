/* brop: the REMOTE-ONLY class (BROP = Blind ROP, Bhatia/Nerdwell).
 * No PIE, no canary, NX on. The service echoes the input through
 * puts() once (the leak oracle + the crash/no-crash detector), then
 * returns - the overflow fires on the return. The binary announces
 * NOTHING: no win function, no gadget addresses, no banner. The
 * exploit measures the offset remotely (crash/no-crash), finds the
 * stop gadget and the BROP gadget (pop rdi; ret) byte by byte, then
 * leaks libc via puts(GOT[puts]) and strikes with system("/bin/sh").
 * Compiled: -fno-stack-protector -no-pie, NX ON, dynamic libc. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* the BROP gadget: the exploit finds it byte by byte over the
 * socket (the binary announces nothing - the walk IS the attack). */
__asm__(
    ".text\n"
    ".globl brop_gadget_asm\n"
    "brop_gadget_asm:\n"
    "    pop %rdi\n"
    "    ret\n"
);
extern void brop_gadget_asm(void);

int vuln(void) {
    char buf[64];
    memset(buf, 0, sizeof buf);
    ssize_t n = read(0, buf, 256);
    if (n <= 0) return 0;
    /* the echo: the only output. The exploit uses it as the leak
     * oracle (return to puts with a controlled rdi) and as the
     * crash/no-crash detector during the offset walk. */
    puts(buf);
    fflush(stdout);
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
