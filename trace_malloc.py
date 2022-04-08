from __future__ import print_function
from bcc import BPF
from sys import stderr
from time import sleep, strftime
import argparse
import errno
import signal

STACK_STORAGE_SIZE = 2048

def positive_int(val):
    try:
        ival = int(val)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")

    if ival < 0:
        raise argparse.ArgumentTypeError("must be positive")
    return ival

def positive_nonzero_int(val):
    ival = positive_int(val)
    if ival == 0:
        raise argparse.ArgumentTypeError("must be nonzero")
    return ival

# arguments
parser = argparse.ArgumentParser(
    description="Summarize libc malloc() bytes by stack trace",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-p", "--pid", metavar="PID", dest="pid",
    help="trace this PID only", type=positive_int)

args = parser.parse_args()
debug = 0

# signal handler
def signal_ignore(signal, frame):
    print()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct mem_event {
    u64 ts;
    u64 data_len;
};

BPF_QUEUE(queue, struct mem_event, 10240);

int trace_malloc(struct pt_regs *ctx, size_t size) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    bpf_trace_printk("SALAM: %d\\n", pid);

    if (FILTER_PID) {
        return 0;
    }

    struct mem_event event = {
        .ts = bpf_ktime_get_ns(),
        .data_len = size
    };
    queue.push(&event, BPF_ANY);
    return 0;
}

"""

# set thread filter
thread_context = ""
if args.pid is not None:
    filter_pid = 'pid != %d' % args.pid
else:
    raise Exception("Specify PID")
bpf_text = bpf_text.replace('FILTER_PID', filter_pid)

if (debug):
    print(bpf_text)

# initialize BPF
b = BPF(text=bpf_text)
b.attach_uprobe(name="c", sym="malloc", fn_name="trace_malloc", pid=args.pid)
matched = b.num_open_uprobes()
if matched == 0:
    print("error: 0 functions traced. Exiting.", file=stderr)
    exit(1)


# output
exiting = 0
interval = 0.001

while 1:
    try:
        sleep(interval)
    except KeyboardInterrupt:
        exiting = 1
    
    has_item = True

    while has_item:
        try:
            event = b["queue"].pop()
            t, data_len = event.ts, event.data_len
            print(t, data_len)
        except KeyError:
            has_item = False


    
    
    if exiting:
        exit()