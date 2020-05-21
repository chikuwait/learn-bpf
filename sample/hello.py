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
bpf.trace_print()
