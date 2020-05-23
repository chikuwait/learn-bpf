from __future__ import print_function
from bcc import BPF
from ctypes import c_ushort, c_int, c_ulonglong
from time import sleep
from sys import argv

def usage():
    print("USAGE: %s [interval [count]]" % argv[0])
    exit()

interval = 5
count = -1
if len(argv) > 1:
    try:
        interval = int(argv[1])
        if interval == 0:
            raise
        if len(argv) >2:
            count = int(argv[2])
    except:
        usage()
bpf = BPF(src_file = "vfsreadlat.c")
bpf.attach_kprobe(event="vfs_read", fn_name="do_entry")
bpf.attach_kretprobe(event="vfs_read",fn_name="do_return")

print("Tracing... Hit Ctrl-C to end.")
loop = 0
do_exit = 0
while(1):
    if count > 0:
        loop += 1
        if loop > count:
            exit()
    try:
        sleep(interval)
    except KeyboardInterrupt:
        pass;do_exit = 1
    print()
    bpf["dist"].print_log2_hist("usecs")
    bpf["dist"].clear()
    if do_exit:
        exit()
