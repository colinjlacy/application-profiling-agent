// agent/bpf/pqexec.bpf.c

// Define target architecture for PT_REGS macros
// Use x86 for GitHub Actions (Ubuntu), change to arm64 for local Mac builds
#define __TARGET_ARCH_x86

// Minimal kernel-style typedefs so bpf_helper_defs.h is happy.
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef unsigned int __wsum;

// Define BPF_MAP_TYPE_RINGBUF constant (from linux/bpf.h)
// We define it here to avoid including linux/bpf.h which has arch-specific dependencies
#define BPF_MAP_TYPE_RINGBUF 27

// For x86_64, manually define struct pt_regs layout (simplified for uprobe parameter access)
#ifndef __aarch64__
struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bp;
    unsigned long bx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long ax;
    unsigned long cx;
    unsigned long dx;
    unsigned long si;
    unsigned long di;
    unsigned long orig_ax;
    unsigned long ip;
    unsigned long cs;
    unsigned long flags;
    unsigned long sp;
    unsigned long ss;
};
#endif

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>  // PT_REGS_PARM* macros

struct event {
    __u64 pid;
    char sql[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} events SEC(".maps");

SEC("uprobe/PQexec")
int trace_pqexec(struct pt_regs *ctx)
{
    struct event *e;
    const char *cmd;

    // Reserve space in ring buffer
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;

    cmd = (const char *)PT_REGS_PARM2(ctx);
    if (cmd) {
        bpf_probe_read_user_str(e->sql, sizeof(e->sql), cmd);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
