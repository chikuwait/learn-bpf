from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from time import sleep

REQ_WRITE = 1
bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HASH(start,struct request *);
BPF_HISTOGRAM(dist);

void trace_start(struct pt_regs *ctx, struct request *req){
    u64 ts = bpf_ktime_get_ns();
    start.update(&req, &ts);
}

void trace_completion(struct pt_regs *ctx, struct request *req){
    u64 *tsp, delta;

    tsp = start.lookup(&req);
    
    if(tsp != 0){
        delta = bpf_ktime_get_ns();
        dist.increment(bpf_log2l(delta/1000));
        start.delete(&req);
    }
}
"""

bpf = BPF(text = bpf_code)

if BPF.get_kprobe_functions(b'blk_start_request'):
    bpf.attach_kprobe(event="blk_start_request", fn_name="trace_start")
bpf.attach_kprobe(event="blk_mq_start_request", fn_name="trace_start")
bpf.attach_kprobe(event="blk_account_io_completion", fn_name="trace_completion")

print("Tracing... Hit Ctrl-C to end.")

try:
    sleep(99999999)
except KeyboardInterrupt:
    print

bpf["dist"].print_log2_hist("usecs")
