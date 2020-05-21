#!/usr/bin/python3

from bcc import BPF

bpf_text ="""
int trace_sys_clone(void *ctx){
    bpf_trace_printk("Hello,world!\\n");
    return 0;
}
"""

bpf = BPF(text=bpf_text)
bpf.attach_kprobe(event="sys_clone", fn_name="trace_sys_clone")
print("%-18s %-16s %-6s %s" %("TIME(S)","COMM","PID","MESSAGE"))
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))

