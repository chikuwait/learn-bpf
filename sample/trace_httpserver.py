from __future__ import print_function
from bcc import BPF, USDT
import sys

bpf_text = """
#include <uapi/linux/ptrace.h>

int do_trace(struct pt_regs *ctx){
    uint64_t addr;
    char path[128] ={0};

    bpf_usdt_readarg(6, ctx, &addr);
    bpf_probe_read_user(&path, sizeof(path), (void *)addr);
    bpf_trace_printk("path:%s\\n", path)l;

    return 0;
}
"""

if len(sys.argv) < 2 :
    print("USAGE: nodejs_http_server PID")
    exit(0)

pid = sys.argv[1]
u = USDT(pid = int(pid))
u.enable_probe(probe = "http__server__request", fn_name = "do_trace")

bpf = BPF(text = bpf_text, usdt_contexts=[u])
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "ARGS"))

while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
    except ValueError:
        print("value error")
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
