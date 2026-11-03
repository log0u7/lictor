/* orw-002: the seccomp target, the STRICTER variant. The filter
 * allows ONLY open/openat/read/write/exit (no execve, no close): the
 * flag is reached through the pure openat/read/write syscall chain.
 * execve DIES with SIGSYS. The banner announces NOTHING (no leak, no
 * win): the path string and the read buffer live in the binary's
 * .data at fixed addresses (no-PIE). Compiled: -fno-stack-protector
 * -no-pie, NX ON (no execstack: no shellcode shortcut either). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <stddef.h>

/* the gadgets the chain needs (the recon convenience: the small
   binary cannot guarantee pop rsi/rdx - the banner announces them) */
__attribute__((noinline)) void pop_rdi_gadget(void) {
    __asm__ volatile("pop %rdi; ret");
}
__attribute__((noinline)) void pop_rsi_gadget(void) {
    __asm__ volatile("pop %rsi; ret");
}
__attribute__((noinline)) void pop_rdx_gadget(void) {
    __asm__ volatile("pop %rdx; ret");
}
__attribute__((noinline)) void pop_rax_gadget(void) {
    __asm__ volatile("pop %rax; ret");
}
__attribute__((noinline)) void syscall_gadget(void) {
    __asm__ volatile("syscall; ret");
}

/* the .data anchors: the flag path string and the read buffer live at
   fixed no-PIE addresses (the exploit aims the openat and the read
   at them offline). */
char flag_path[] = "orw-002.flag";
char out_buf[256];

void install_filter(void) {
    /* allow ONLY: open(2) openat(257) read(0) write(1) exit(60)
     * exit_group(231). Everything else - execve(59) included - dies
     * with SIGSYS. The banner announces nothing: the filter is the
     * recon surface the operator reads from the binary. */
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_open, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_read, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit_group, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)
    };
    struct sock_fprog prog = {14, filter};
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

int vuln_copy(const char *src, size_t n) {
    /* the copy is bounded by the read length (memcpy, not strcpy):
       the ROP chain carries NUL-bearing addresses (0x100 read size,
       the .data anchors) - the read channel crosses them whole. */
    char small[8];
    memcpy(small, src, n);
    return (int) n;
}

int main(void) {
    char input[512];
    ssize_t n;
    int fd;

    setvbuf(stdout, NULL, _IONBF, 0);
    /* the fd hygiene: the socat wrapper leaks stray descriptors into
     * the child (the socketpair ends, the accepted socket, the log
     * file) - the openat in the exploit chain expects the flag file to
     * land on a KNOWN low fd. close() is unrestricted BEFORE the filter
     * installs: the service reclaims the low slot numbers itself. */
    for (fd = 3; fd < 16; fd++) close(fd);
    install_filter();
    puts("orw-002 target - the filter allows ONLY open/openat/read/write/exit");
    /* the gadgets the chain needs: the banner announces them (the
       recon convenience - the small binary's own gadgets). */
    char banner[224];
    snprintf(banner, sizeof(banner),
             "rdi() at %p rsi() at %p rdx() at %p rax() at %p syscall() at %p",
             (void *) &pop_rdi_gadget, (void *) &pop_rsi_gadget,
             (void *) &pop_rdx_gadget, (void *) &pop_rax_gadget,
             (void *) &syscall_gadget);
    puts(banner);
    fputs("name? ", stdout);
    n = read(0, input, sizeof(input) - 1);
    if (n <= 0) return 1;
    input[n - 1] = 0;
    vuln_copy(input, (size_t) n);
    fputs("hello\n", stdout);
    return 0;
}
