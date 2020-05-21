from bcc import BPF

bpf_code ="""
#include <linux/sched.h>

struct data_t  {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

int hello(struct pt_regs *ctx){
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

bpf = BPF(text = bpf_code)
bpf.attach_kprobe(event = bpf.get_syscall_fnname("clone"), fn_name = "hello");

print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

start =0
def print_event(cpu, data, size):
    global start
    event  = bpf["events"].event(data)

    if start == 0:
        start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print("%-18.9f %-16s %-6d %s" % (time_s, event.comm, event.pid, "Hello, perf_output!"))

bpf["events"].open_perf_buffer(print_event)
while 1:
    bpf.perf_buffer_poll()
