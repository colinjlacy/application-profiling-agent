// agent/bpf/pqexec.bpf.c

// Define target architecture for PT_REGS macros
#define __TARGET_ARCH_arm64

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

#include <linux/bpf.h>
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
