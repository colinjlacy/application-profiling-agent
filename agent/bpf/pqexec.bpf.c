// agent/bpf/pqexec.bpf.c

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>  // PT_REGS_PARM* macros

struct event {
    unsigned long long pid;  // avoid __u64 to skip linux/types.h
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
