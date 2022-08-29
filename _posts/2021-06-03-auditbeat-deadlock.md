---
layout: post
tags: auditbeat deadlock linux
title: auditbeat deadlock
categories: Linux
date: 2021-06-03 14:02:32-0700
excerpt: auditbeat deadlock
---

## Phenomenon
User can't run sudo in their container

## Debug
* There are lots of cron and sudo processes stuck in D status

![](/assets/2021-06-03-auditbeat-deadlock-phenomenon.png)

* Check the process’s stack.  Sudo and cron process will send audit logs through netlink to auditbeat, but they stucked, and then become to D state.

```
    [<0>] audit_receive+0x28/0xc0
    [<0>] netlink_unicast+0x197/0x220
    [<0>] netlink_sendmsg+0x227/0x3d0
    [<0>] sock_sendmsg+0x63/0x70
    [<0>] __sys_sendto+0x114/0x1a0
    [<0>] __x64_sys_sendto+0x28/0x30
    [<0>] do_syscall_64+0x57/0x190
    [<0>] entry_SYSCALL_64_after_hwframe+0x44/0xa9

```

From the disassembly code of function audit_receive(), we can see that it stuck at try to acquire a lock in audit_receive()

![](/assets/2021-06-03-auditbeat-deadlock-audit-receive.png)

* Try to find out which process is holding this lock, and we can see that it is hold by auditbeat.

```
cat /proc/248085/stat;cat /proc/248085/stack;cat /proc/248085/stat;cat /proc/248085/stack;cat /proc/248085/net/netlink

248085 (auditbeat) S 247759 247832 247832 0 -1 4194624 656934 0 5080 0 47087 8935 0 0 20 0 77 0 48038941 4420079616 53081 18446744073709551615 4194304 38844573 140728827925408 0 0 0 0 0 2143420159 0 0 0 -1 55 0 0 0 0 0 65563728 67515520 74981376 140728827930392 140728827930481 140728827930481 140728827932639 0
       [<0>] netlink_attachskb+0x1ab/0x1d0
       [<0>] netlink_unicast+0xab/0x220
       [<0>] audit_receive_msg+0x54c/0xeb0
       [<0>] audit_receive+0x57/0xc0
       [<0>] netlink_unicast+0x197/0x220
       [<0>] netlink_sendmsg+0x227/0x3d0
       [<0>] sock_sendmsg+0x63/0x70
       [<0>] __sys_sendto+0x114/0x1a0
       [<0>] __x64_sys_sendto+0x28/0x30
       [<0>] do_syscall_64+0x57/0x190
       [<0>] entry_SYSCALL_64_after_hwframe+0x44/0xa9

248085 (auditbeat) S 247759 247832 247832 0 -1 4194624 656934 0 5080 0 47087 8935 0 0 20 0 77 0 48038941 4420079616 53081 18446744073709551615 4194304 38844573 140728827925408 0 0 0 0 0 2143420159 0 0 0 -1 55 0 0 0 0 0 65563728 67515520 74981376 140728827930392 140728827930481 140728827930481 140728827932639 0
       [<0>] netlink_attachskb+0x1ab/0x1d0
       [<0>] netlink_unicast+0xab/0x220
       [<0>] audit_receive_msg+0x54c/0xeb0
       [<0>] audit_receive+0x57/0xc0
       [<0>] netlink_unicast+0x197/0x220
       [<0>] netlink_sendmsg+0x227/0x3d0
       [<0>] sock_sendmsg+0x63/0x70
       [<0>] __sys_sendto+0x114/0x1a0
       [<0>] __x64_sys_sendto+0x28/0x30
       [<0>] do_syscall_64+0x57/0x190
       [<0>] entry_SYSCALL_64_after_hwframe+0x44/0xa9

```

From the disassemble code, we can see that the process become sleep and schedule out at:

![](/assets/2021-06-03-auditbeat-deadlock-netlink-attachskb.png)

The reason is sk->sk_rmem_alloc > sk->sk_rcvbuf, because we can see that the rmem of auditbeat is full by 'ss -f netlink -e|grep -i auditbeat'


```
    214272 0           audit:auditbeat/247832       *       sk=0 cb=0 groups=0x00000000
```


* Use pprof to get auditbeat's stack, and the related stack for this lock is:

```
            syscall.Syscall6
            syscall.sendto
            syscall.Sendto
            github.com/elastic/go-libaudit/v2.(*NetlinkClient).Send
            github.com/elastic/go-libaudit/v2.(*AuditClient).set
            github.com/elastic/go-libaudit/v2.(*AuditClient).Close.func1
            sync.(*Once).doSlow
            sync.(*Once).Do (inline)
            github.com/elastic/go-libaudit/v2.(*AuditClient).Close
            github.com/elastic/beats/v7/auditbeat/module/auditd.(*MetricSet).Run
            github.com/elastic/beats/v7/metricbeat/mb/module.(*metricSetWrapper).run
            github.com/elastic/beats/v7/metricbeat/mb/module.(*Wrapper).Start.func1
```

There is a goroutine want to close the audit client, and is blocked at setPid() operation.

* Check auditbeat's code
![](/assets/2021-06-03-auditbeat-deadlock-close.png)
It will do setPID() operation before closing the netlink socket.
setPID() makes the kernel send the audit info back to auditbeat, but since the auditbeat’s rcvbuf is full, it sleeps after holding the lock.
Then other processes like sudo and cron want to send the messages to auditbeat will  also be stuck and become D.

* Since auditbeat process is in Sleep status, so we can kill the auditbeat process to make the system recover.

* How to fix
There is an upstream issue for this in almost the same time: https://github.com/elastic/beats/issues/26031
Fix for this:  https://github.com/elastic/beats/pull/26032
