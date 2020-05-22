from __future__ import print_function
from bcc import BPF
from time import sleep

bpf = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HISTOGRAM(dist);

int kprobe__blk_account_io_completion(struct pt_regs *ctx, struct request *req){
    dist.increment(bpf_log2l(req->__data_len / 1024));
    return 0;
}

""")

print("Tracing... Hit Ctrl-C to end.")
try:
	sleep(99999999)
except KeyboardInterrupt:
	print()
bpf["dist"].print_log2_hist("kbytes")

