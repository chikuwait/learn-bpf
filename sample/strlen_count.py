from __future__ import print_function
from bcc import BPF
from time import sleep

bpf = BPF(text ="""
#include <uapi/linux/ptrace.h>

struct key_t{
    char c[80];
};
BPF_HASH(counts, struct key_t);

int count(struct pt_regs *ctx){
    if (!PT_REGS_PARM1(ctx)){
        return 0;
    }

    struct key_t key = {};
    u64 zero =0, *val;

    bpf_probe_read(&key.c, sizeof(key.c), (void *)PT_REGS_PARM1(ctx));
    val = counts.lookup_or_init(&key, &zero);
    if(val){
        (*val)++;
    }
    return 0;
}
""")

bpf.attach_uprobe(name="c", sym = "strlen", fn_name = "count")
print("Tracing strlen()... Hit Ctrl-C to end.")

try:
    sleep(99999999)
except KeyboardInterrupt:
    pass

print("%10s %s" % ("COUNT", "STRING"))
counts = bpf.get_table("counts")
for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    print("%10d \"%s\"" % (v.value, k.c.encode('string-escape')))
