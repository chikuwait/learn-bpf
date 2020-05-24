#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct key_t{
    u32 prev_pid;
    u32 curr_pid;
}

BPF_HASH(stats, struct key_t, u64, 1024);
int count_sched(struct pt_regs *ctx, struct task_struct *prev){
    struct key_t key = {};

    key.curr_pid = bpf_get_current_pid_tgid();
    key.prev_pid = prev->pid;

    stats.increment(key);

    return 0;
}
