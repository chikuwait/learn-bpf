from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

bpf_txt = """
#include <uapi/linux/ptrace.h>
struct data_t{
    u64 delta;
    u32 pid;
    u64 time;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(last);

int do_trace(struct pt_regs *ctx){
  u64 ts, *tsp, delta, key=0;
  struct data_t msg = {};

  tsp = last.lookup(&key);
  if(tsp != 0){
    delta = bpf_ktime_get_ns() - *tsp;
    if(delta <1000000000){
        msg.pid = bpf_get_current_pid_tgid();
        msg.delta = delta / 1000000;
        msg.time = bpf_ktime_get_ns();
        events.perf_submit(ctx, &msg, sizeof(msg));
    }
    last.delete(&key);
  }
  ts = bpf_ktime_get_ns();
  last.update(&key, &ts);
  return 0;
}
"""
start = 0
def print_event(cpu, data, size):
    global start
    event = bpf["events"].event(data)

    if start == 0:
        start = int(event.time)
    time_s = (int(event.time) - start) / 1000000000
    print("[PID:%d] At time %d ms: multiple syncs detected, last %s ms ago" % (event.pid, time_s, event.delta))


bpf = BPF(text=bpf_txt)
bpf.attach_kprobe(event=bpf.get_syscall_fnname("sync"),fn_name="do_trace")
bpf["events"].open_perf_buffer(print_event)

print("Tracing for quick sync's... Ctrl-C to end")
while 1:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
