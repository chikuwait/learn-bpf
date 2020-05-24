from bcc import BPF
from time import sleep

bpf = BPF(src_file="task_switch.c")
bpf.attach_kprobe(event="finish_task_switch", fn_name="count_sched")

for i in range(0, 100): sleep(0.01)

for item, _ in bpf["stats"].items():
    print("task_switch[%5d->%5d]" % (item.prev_pid, item.curr_pid))
