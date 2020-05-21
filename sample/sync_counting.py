from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

bpf_txt = """
#include <uapi/linux/ptrace.h>

BPF_HASH(last);

int do_trace(struct pt_regs *ctx){
  u64 ts, *tsp, delta, key = 0, index = 1, count = 1;
  tsp = last.lookup(&key);
  if(tsp != 0){
    delta = bpf_ktime_get_ns() - *tsp;
    if(delta <1000000000){
        tsp = last.lookup(&index);
        if(tsp != 0){
            count = *tsp;
            count++;
        }
        bpf_trace_printk("%d,%d\\n",count, delta / 1000000);
    }
    last.delete(&key);
    last.delete(&index);
  }
  ts = bpf_ktime_get_ns();
  last.update(&key, &ts);
  last.update(&index, &count);
  return 0;
}

"""

bpf = BPF(text=bpf_txt)
bpf.attach_kprobe(event=bpf.get_syscall_fnname("sync"),fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end")

start = 0
while 1:
    (task,pid,cpu,flags,ts,msg) = bpf.trace_fields()
    [cnt, ms] = msg.decode('utf-8').split(",")
    if start == 0:
        start = ts
    ts = ts - start
    print("At time %.2f s: %s syncs detected, last %s ms ago" % (ts, cnt, ms))
