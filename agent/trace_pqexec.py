#!/usr/bin/env python3
import os
import time
import ctypes
from bcc import BPF

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>

struct data_t {
    u64 pid;
    char sql[256];
};

BPF_PERF_OUTPUT(events);

int trace_pqexec(struct pt_regs *ctx) {
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;

    const char *cmd = (const char *)PT_REGS_PARM2(ctx);
    if (cmd) {
        bpf_probe_read_user_str(&data.sql, sizeof(data.sql), cmd);
    }

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

class Data(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_ulonglong),
        ("sql", ctypes.c_char * 256),
    ]

def find_target_pid(pattern: str) -> int | None:
    """Find a PID whose cmdline contains the given pattern."""
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read().replace(b"\x00", b" ")
        except OSError:
            continue
        if pattern.encode("utf-8") in cmdline:
            return pid
    return None

def main():
    target_pattern = os.environ.get("TARGET_PATTERN", "testapp")
    output_path = os.environ.get("OUTPUT_FILE", "/output/pqexec.log")

    print(f"[agent] waiting for process with cmdline matching '{target_pattern}'...")
    pid = None
    while pid is None:
        pid = find_target_pid(target_pattern)
        if pid is None:
            time.sleep(1)
    print(f"[agent] found target PID = {pid}")

    # Build path to libpq as seen from that process's root
    libpq_path = f"/proc/{pid}/root/usr/lib/aarch64-linux-gnu/libpq.so.5"
    if not os.path.exists(libpq_path):
        raise SystemExit(f"[agent] libpq not found at {libpq_path}")

    print(f"[agent] attaching uprobe to PQexec in {libpq_path}")

    b = BPF(text=BPF_PROGRAM)
    b.attach_uprobe(name=libpq_path, sym="PQexec", fn_name="trace_pqexec")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    outf = open(output_path, "a", buffering=1)
    print(f"[agent] logging PQexec calls to {output_path}")

    def handle_event(cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(Data)).contents
        sql = event.sql.decode("utf-8", errors="replace").rstrip("\x00")
        line = f"pid={event.pid} PQexec sql={sql}\n"
        outf.write(line)
        # Also show it on stdout for convenience
        print(line, end="")

    b["events"].open_perf_buffer(handle_event)

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("[agent] exiting...")
    finally:
        outf.close()

if __name__ == "__main__":
    main()
