---
layout: post
tags: eBPF linux
title: pid id in container
categories: eBPF
date: 2022-09-02 14:02:32-0700
excerpt: pid id in container
---

## Question
I am working on making eBPF tools can be triggered by user. 
One feature provided to user is:
* User can profile all the Processes/Tasks for specific container
* User can profile any process for specific container

For 2, User can provide the container ns/name and process id inside the container.
Since there is pid namespace isolation, so we need to convert process id provided by user to the id in host pid namespace.

## bpf helper function

There is a bpf helper function for pid mapping. 

Context info:

https://man7.org/linux/man-pages/man7/bpf-helpers.7.html

https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#12-bpf_get_ns_current_pid_tgid

https://lore.kernel.org/bpf/20191017150032.14359-3-cneirabustos@gmail.com/

https://lwn.net/Articles/807741/

The API is:
```
       long bpf_get_ns_current_pid_tgid(u64 dev, u64 ino, struct
       bpf_pidns_info *nsdata, u32 size)
              Description
                     Returns 0 on success, values for pid and tgid as
                     seen from the current namespace will be returned in
                     nsdata.

              Return 0 on success, or one of the following in case of
                     failure:

                     -EINVAL if dev and inum supplied don't match dev_t
                     and inode number with nsfs of current task, or if
                     dev conversion to dev_t lost high bits.

                     -ENOENT if pidns does not exists for the current
                     task.
```

## Test

* How to get the dev and ino for a pid?

```
stat -L /proc/190579/ns/pid
  File: /proc/190579/ns/pid
  Size: 0         	Blocks: 0          IO Block: 4096   regular empty file
Device: 4h/4d	Inode: 4026533397  Links: 1
Access: (0444/-r--r--r--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2022-09-01 19:54:44.448346607 -0700
Modify: 2022-09-01 19:54:44.448346607 -0700
Change: 2022-09-01 19:54:44.448346607 -0700
 Birth: -
```

* Test code

```
#!/usr/bin/python
from bcc import BPF
from bcc.utils import printb
import sys, os
from stat import *

# define BPF program
prog = """
#include <linux/sched.h>
// define output data structure in C
struct data_t {
    u32 pid;
    u32 tgid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);
int hello(struct pt_regs *ctx) {
    struct data_t data = {};
    struct bpf_pidns_info ns = {};
    if(bpf_get_ns_current_pid_tgid(DEV, INO, &ns, sizeof(struct bpf_pidns_info)))
        return 0;
    data.pid = ns.pid;
    data.tgid = ns.tgid;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

devinfo = os.stat("/proc/71088/ns/pid")

print(devinfo.st_dev,devinfo.st_ino)

for r in (("DEV", str(devinfo.st_dev)), ("INO", str(devinfo.st_ino))):
    prog = prog.replace(*r)

# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("write"), fn_name="hello")

# header
print("%-18s %-16s %-6s %-6s %s" % ("TIME(s)", "COMM", "PID", "TGID", "MESSAGE"))

# process event
start = 0


def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
        start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    printb(
        b"%-18.9f %-16s %-6d %-6d %s"
        % (time_s, event.comm, event.pid, event.tgid, b"Hello, perf_output!")
    )


# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
```

* Test Result

```
root@xxxxx:~# python2 test.py 
(4, 4026536448)
TIME(s)            COMM             PID    TGID   MESSAGE
0.000000000        etcd             34     1      Hello, perf_output!
0.003570885        etcd             34     1      Hello, perf_output!
0.009293641        etcd             142    1      Hello, perf_output!
0.009399447        etcd             142    1      Hello, perf_output!
0.009768254        etcd             34     1      Hello, perf_output!
0.009982884        etcd             142    1      Hello, perf_output!
0.154406187        etcd             142    1      Hello, perf_output!
0.156417123        etcd             144    1      Hello, perf_output!
0.156780100        etcd             144    1      Hello, perf_output!
0.157019835        etcd             142    1      Hello, perf_output!
```

* Login to the container and check for the process id

```
root@xxxxxx:~# crictl exec -it bae49309d79fc sh  
/ # ps -ef
PID   USER     TIME  COMMAND
    1 root      1h23 /usr/local/bin/etcd --data-dir=/var/etcd/data --name=etcd-events-0037 --initial-advertise-peer-urls=https://xxxxxx:2380 --listen-peer-urls=https://0.0.0.0:2380 --listen-clie
50615 root      0:00 sh
50621 root      0:00 ps -ef
```

### Support kernel

Linux 5.6+ 
