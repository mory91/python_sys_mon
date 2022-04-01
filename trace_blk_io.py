from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
from subprocess import call

parser = argparse.ArgumentParser(
        description="Block device (disk) I/O of a process",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
parser.add_argument("-p", "--pid", type=int, metavar="PID",
    help="trace this PID only")
args = parser.parse_args()

# linux stats
loadavg = "/proc/loadavg"
diskstats = "/proc/diskstats"

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

// for saving the timestamp and __data_len of each request
struct read_event {
    u64 ts;
    u64 data_len;
};

BPF_QUEUE(queue, struct read_event, 10240);

// time block I/O
int trace_req_start(struct pt_regs *ctx, struct request *req)
{   
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (FILTER_PID)
        return 0;
    
    struct read_event event = {
        .ts = bpf_ktime_get_ns(),
        .data_len = req->__data_len
    };
    queue.push(&event, BPF_ANY);
    return 0;
}

"""


if args.pid is not None:
    bpf_text = bpf_text.replace('FILTER_PID', 'pid != %d' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER_PID', '0')

b = BPF(text=bpf_text)
if BPF.get_kprobe_functions(b'blk_start_request'):
    b.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")


print('Tracing...')


# output
exiting = 0
interval = 1

while 1:
    try:
        sleep(interval)
    except KeyboardInterrupt:
        exiting = 1

    print()
    


    
    try:
        event = b["queue"].pop()
        t, data_len = event.ts, event.data_len
        print(t, data_len)
    except KeyError:
        print("XXXXXXXXXXXXXXXXXXX")

    
    
    if exiting:
        exit()
