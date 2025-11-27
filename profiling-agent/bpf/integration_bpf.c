// bpf/integration_bpf.c

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Logical hook IDs so user space knows how to decode.
enum hook_id {
    HOOK_CONNECT = 1,
    HOOK_OPENAT  = 2,
    HOOK_PQEXEC  = 3,
};

// Generic event, kept pretty small for ringbuf.
struct event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    __u32 hook_id;

    // Generic payload fields. Meaning depends on hook_id.
    __u64 num1;
    __u64 num2;

    char  str1[128];
    char  str2[256];
};

// Ring buffer for events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} events SEC(".maps");

static __always_inline int emit_event(struct event *e)
{
    int ret = bpf_ringbuf_output(&events, e, sizeof(*e), 0);
    return ret;
}

// Helper to get pid/tid and timestamp.
static __always_inline void init_event(struct event *e, __u32 hook_id)
{
    __u64 id = bpf_get_current_pid_tgid();
    e->ts_ns = bpf_ktime_get_ns();
    e->pid   = id >> 32;
    e->tid   = (__u32)id;
    e->hook_id = hook_id;
}

// ========== kprobe: connect ==========
//
// int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
// We extract family, IP, port into str1/num1/num2 for now.

SEC("kprobe/connect")
int kprobe_connect(struct pt_regs *ctx)
{
    struct event e = {};
    init_event(&e, HOOK_CONNECT);

    int sockfd;
    const struct sockaddr *addr;
    socklen_t addrlen;

    sockfd = (int)PT_REGS_PARM1(ctx);
    addr   = (const struct sockaddr *)PT_REGS_PARM2(ctx);
    addrlen = (socklen_t)PT_REGS_PARM3(ctx);

    e.num1 = sockfd;

    // Read family
    __u16 family = 0;
    bpf_core_read_user(&family, sizeof(family), &addr->sa_family);

    if (family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in sin = {};
        bpf_core_read_user(&sin, sizeof(sin), addr);

        __u32 ip = __builtin_bswap32(sin.sin_addr.s_addr);
        __u16 port = __builtin_bswap16(sin.sin_port);

        e.num2 = port;

        // Very crude dotted-quad; you might want to just store ip as num.
        __u8 b1 = (ip >> 24) & 0xff;
        __u8 b2 = (ip >> 16) & 0xff;
        __u8 b3 = (ip >> 8)  & 0xff;
        __u8 b4 = ip & 0xff;
        e.str1[0] = '0' + (b1 / 100 % 10); // placeholder; better to keep ip as num
        // For brevity we won’t format full IP here; user-space can read e.numX instead.
    } else if (family == AF_INET6 && addrlen >= sizeof(struct sockaddr_in6)) {
        // You can add IPv6 handling later; for now we just record family.
        e.num2 = 0;
    }

    emit_event(&e);
    return 0;
}

// ========== kprobe: openat ==========
//
// int openat(int dirfd, const char *pathname, int flags, mode_t mode)

SEC("kprobe/openat")
int kprobe_openat(struct pt_regs *ctx)
{
    struct event e = {};
    init_event(&e, HOOK_OPENAT);

    int dirfd = (int)PT_REGS_PARM1(ctx);
    const char *pathname = (const char *)PT_REGS_PARM2(ctx);
    int flags = (int)PT_REGS_PARM3(ctx);

    e.num1 = dirfd;
    e.num2 = flags;

    // Read up to sizeof(str1)-1 bytes of the pathname.
    bpf_core_read_user_str(e.str1, sizeof(e.str1), pathname);

    emit_event(&e);
    return 0;
}

// ========== uprobe: PQexec (Postgres) ==========
//
// PGresult *PQexec(PGconn *conn, const char *command);
//
// We'll attach this uprobe to libpq.so.5 in user-space. We read the SQL text.

SEC("uprobe/PQexec")
int uprobe_PQexec(struct pt_regs *ctx)
{
    struct event e = {};
    init_event(&e, HOOK_PQEXEC);

    void *conn = (void *)PT_REGS_PARM1(ctx);
    const char *command = (const char *)PT_REGS_PARM2(ctx);

    // Store conn pointer as num1, just for correlation if needed.
    e.num1 = (__u64)conn;

    // Read the SQL string into str1.
    bpf_core_read_user_str(e.str1, sizeof(e.str1), command);

    emit_event(&e);
    return 0;
}
