from __future__ import print_function
from bcc import BPF

bpf = BPF(text= """
TRACEPOINT_PROBE(random, urandom_read){
    bpf_trace_printk("%d\\n", args->got_bit);
    return 0;
}
"""
)

print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "GOTBITS"))
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = bpf.trace_fileds()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))

