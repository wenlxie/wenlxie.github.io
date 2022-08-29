#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime
import time
import ctypes as ct
import sys

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
struct xfs_lock
{
    u32 func;
    u32 pid;
    void *xfs_buf;
    void *task_struct;
    u32 ret;
    u32 stack;
    u64 start_timestamp;
};
BPF_PERF_OUTPUT(xfs_lock_event);
BPF_STACK_TRACE(stack_traces, 10240);
int kprobe__xfs_buf_lock(struct pt_regs *ctx)
{
	struct xfs_lock data = {};
	data.func = 1;
	data.pid = (u32)bpf_get_current_pid_tgid();
	data.xfs_buf = (void *)PT_REGS_PARM1(ctx);
	data.task_struct = (void*)bpf_get_current_task();
	data.ret = 0;
	data.stack = stack_traces.get_stackid(ctx, 0);
	data.start_timestamp = bpf_ktime_get_ns();
	xfs_lock_event.perf_submit(ctx, &data, sizeof(data));
	return 0;
}
int kprobe__xfs_buf_unlock(struct pt_regs *ctx)
{
	
	struct xfs_lock data = {};
	data.func = 2;
	data.pid = (u32)bpf_get_current_pid_tgid();
	data.xfs_buf = (void *)PT_REGS_PARM1(ctx);
	data.task_struct = (void*)bpf_get_current_task();
	data.ret = 0;
	data.stack = stack_traces.get_stackid(ctx, 0);
	data.start_timestamp = bpf_ktime_get_ns();
	xfs_lock_event.perf_submit(ctx, &data, sizeof(data));
	return 0;
}
int kprobe__xfs_buf_trylock(struct pt_regs *ctx)
{
	struct xfs_lock data = {};
	data.func = 3;
	data.pid = (u32)bpf_get_current_pid_tgid();
	data.xfs_buf = (void *)PT_REGS_PARM1(ctx);
	data.task_struct = (void*)bpf_get_current_task();
	data.ret = 0;
	data.stack = stack_traces.get_stackid(ctx, 0);
	data.start_timestamp = bpf_ktime_get_ns();
	xfs_lock_event.perf_submit(ctx, &data, sizeof(data));
	return 0;
}
int kretprobe__xfs_buf_trylock(struct pt_regs *ctx)
{
	struct xfs_lock data = {};
	data.func = 4;
	data.pid = (u32)bpf_get_current_pid_tgid();
	data.xfs_buf = (void *)PT_REGS_PARM1(ctx);
	data.task_struct = (void*)bpf_get_current_task();
	data.ret = PT_REGS_RC(ctx);
	data.stack = stack_traces.get_stackid(ctx, 0);
	data.start_timestamp = bpf_ktime_get_ns();
	xfs_lock_event.perf_submit(ctx, &data, sizeof(data));
	return 0;
}
"""

class TestEvt(ct.Structure):
    _fields_ = [
        ("func",       ct.c_uint),
        ("pid",         ct.c_uint),
        ("xfs_buf",       ct.c_ulonglong),
        ("task_struct",       ct.c_ulonglong),
        ("ret",       ct.c_uint),
        ("stack",       ct.c_uint),
        ("start_timestamp",    ct.c_ulonglong),
    ]


def event_printer(cpu, data, size):
    # Decode event
    event = ct.cast(data, ct.POINTER(TestEvt)).contents

    print ("[%s] [%s] %s %x %x %s" % (event.start_timestamp, event.func, event.pid,event.xfs_buf,event.task_struct, event.ret))

    for addr in stack_traces.walk(event.stack):
        sym = b.ksym(addr, show_offset=True)
        print("\t%s" % sym)


if __name__ == "__main__":
    b = BPF(text=bpf_text)
    b["xfs_lock_event"].open_perf_buffer(event_printer)
    stack_traces = b.get_table("stack_traces")

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        sys.exit(0)