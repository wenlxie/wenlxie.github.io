---
layout: post
tags: xfs deadlock linux
title: overlayfs over xfs deadlock
categories: Linux
date: 2020-09-15 14:02:32-0700
excerpt: xfs deadlock
---

## Phenomenon
In our DC, some of k8s's minion nodes are using [Ubuntu Linux 5.4](https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/focal/tag/?h=Ubuntu-5.4.0-34.38) 
to do the test. 
We have some containers using the same base image and start script. 
Sometimes that many processes will come into D state.

Some of the process that come into D state are:

```
crash> foreach UN ps -m |sort|tail
[0 16:55:33.313] [UN]  PID: 148201  TASK: ffff89610e331ec0  CPU: 33  COMMAND: "checkCustom"
[0 16:55:33.885] [UN]  PID: 147963  TASK: ffff894bd4845c40  CPU: 16  COMMAND: "network_mon"
[0 16:55:33.941] [UN]  PID: 147952  TASK: ffff89667c833d80  CPU: 3   COMMAND: "disk_mon"
[0 16:55:34.831] [UN]  PID: 147702  TASK: ffff896225998000  CPU: 34  COMMAND: "mv"
[0 16:55:36.268] [UN]  PID: 146103  TASK: ffff896bc51bdc40  CPU: 7   COMMAND: "checkCPU"
[0 16:55:36.579] [UN]  PID: 2690   TASK: ffff896e75769ec0  CPU: 10  COMMAND: "containerd"
[0 16:55:37.063] [UN]  PID: 16429  TASK: ffff896e77039ec0  CPU: 39  COMMAND: "runsv"
[0 16:55:37.537] [UN]  PID: 147220  TASK: ffff8968e5305c40  CPU: 32  COMMAND: "mv"
[0 16:55:37.537] [UN]  PID: 147221  TASK: ffff895d140d0000  CPU: 10  COMMAND: "mv"
[0 16:55:37.540] [UN]  PID: 147222  TASK: ffff896278ee3d80  CPU: 26  COMMAND: "mv"
```

There are containers using the same image, and do 
`mv /etc/security/access.conf /etc/security/access.conf.bak` operations after start.

```
crash> ps -p 147222
PID: 0      TASK: ffffffff86a13780  CPU: 0   COMMAND: "swapper/0"
 PID: 1      TASK: ffff896737dedc40  CPU: 38  COMMAND: "systemd"
  PID: 25742  TASK: ffff895e24405c40  CPU: 13  COMMAND: "containerd"
   PID: 32242  TASK: ffff895337bb1ec0  CPU: 20  COMMAND: "containerd-shim"
    PID: 32317  TASK: ffff895c3b288000  CPU: 27  COMMAND: "run.sh"
     PID: 147222  TASK: ffff896278ee3d80  CPU: 26  COMMAND: "mv"

crash> ps -p 147221
PID: 0      TASK: ffffffff86a13780  CPU: 0   COMMAND: "swapper/0"
 PID: 1      TASK: ffff896737dedc40  CPU: 38  COMMAND: "systemd"
  PID: 17972  TASK: ffff8967372d0000  CPU: 14  COMMAND: "containerd"
   PID: 26289  TASK: ffff896e770d3d80  CPU: 16  COMMAND: "containerd-shim"
    PID: 26333  TASK: ffff8958a7c38000  CPU: 10  COMMAND: "run.sh"
     PID: 147221  TASK: ffff895d140d0000  CPU: 10  COMMAND: "mv"

crash> ps -p 147220
PID: 0      TASK: ffffffff86a13780  CPU: 0   COMMAND: "swapper/0"
 PID: 1      TASK: ffff896737dedc40  CPU: 38  COMMAND: "systemd"
  PID: 3315   TASK: ffff896ad717bd80  CPU: 28  COMMAND: "containerd"
   PID: 38825  TASK: ffff89654b693d80  CPU: 22  COMMAND: "containerd-shim"
    PID: 38950  TASK: ffff895c38c73d80  CPU: 32  COMMAND: "run.sh"
     PID: 147220  TASK: ffff8968e5305c40  CPU: 32  COMMAND: "mv"

crash> ps -p 16429
PID: 0      TASK: ffffffff86a13780  CPU: 0   COMMAND: "swapper/0"
 PID: 1      TASK: ffff896737dedc40  CPU: 38  COMMAND: "systemd"
  PID: 3315   TASK: ffff896ad717bd80  CPU: 28  COMMAND: "containerd"
   PID: 15723  TASK: ffff8958b5d23d80  CPU: 14  COMMAND: "containerd-shim"
    PID: 15747  TASK: ffff896e71c41ec0  CPU: 29  COMMAND: "my_init"
     PID: 16428  TASK: ffff896562fc8000  CPU: 34  COMMAND: "runsvdir"
      PID: 16429  TASK: ffff896e77039ec0  CPU: 39  COMMAND: "runsv"
```
The stacks are
```
crash> bt -t 147222
PID: 147222  TASK: ffff896278ee3d80  CPU: 26  COMMAND: "mv"
              START: __schedule at ffffffff85ea4cc6
  [ffff9e33ab0df6c0] __schedule at ffffffff85ea4cc6
  [ffff9e33ab0df700] xfs_buf_find at ffffffffc0457435 [xfs]
  [ffff9e33ab0df720] schedule at ffffffff85ea5103
  [ffff9e33ab0df738] schedule_timeout at ffffffff85ea8a65
  [ffff9e33ab0df798] xfs_buf_find at ffffffffc0457435 [xfs]
  [ffff9e33ab0df7b8] __down at ffffffff85ea7756
  [ffff9e33ab0df810] down at ffffffff85500f91
  [ffff9e33ab0df830] xfs_buf_lock at ffffffffc0456fa7 [xfs]
  [ffff9e33ab0df858] xfs_buf_find at ffffffffc0457435 [xfs]
  [ffff9e33ab0df8e8] xfs_buf_get_map at ffffffffc0457743 [xfs]
  [ffff9e33ab0df938] xfs_buf_read_map at ffffffffc0457fab [xfs]
  [ffff9e33ab0df980] xfs_trans_read_buf_map at ffffffffc04906e9 [xfs]
  [ffff9e33ab0df9c0] xfs_read_agi at ffffffffc0439783 [xfs]
  [ffff9e33ab0dfa20] xfs_iunlink at ffffffffc046ca7b [xfs]
  [ffff9e33ab0dfa30] current_time at ffffffff856f9921
  [ffff9e33ab0dfa80] xfs_droplink at ffffffffc046cc24 [xfs]
  [ffff9e33ab0dfaa0] xfs_rename at ffffffffc087fab2 [livepatch_93597ae8]
  [ffff9e33ab0dfb70] xfs_vn_rename at ffffffffc046a0b3 [xfs]
  [ffff9e33ab0dfbe8] vfs_rename at ffffffff856e9955
  [ffff9e33ab0dfc60] d_lookup at ffffffff856f88da
  [ffff9e33ab0dfca0] ovl_do_rename at ffffffffc0d0e2bc [overlay]
  [ffff9e33ab0dfce0] ovl_rename at ffffffffc0d0f557 [overlay]
  [ffff9e33ab0dfd98] vfs_rename at ffffffff856e9955
  [ffff9e33ab0dfe10] __lookup_hash at ffffffff856e6c94
  [ffff9e33ab0dfe50] do_renameat2 at ffffffff856ed168
  [ffff9e33ab0dff20] __x64_sys_rename at ffffffff856ed3e0
  [ffff9e33ab0dff30] do_syscall_64 at ffffffff85404447
  [ffff9e33ab0dff50] entry_SYSCALL_64_after_hwframe at ffffffff8600008c
    RIP: 00007fdb71618367  RSP: 00007ffce72ad108  RFLAGS: 00000202
    RAX: ffffffffffffffda  RBX: 0000000000008000  RCX: 00007fdb71618367
    RDX: 0000000000000000  RSI: 00007ffce72af1aa  RDI: 00007ffce72af19d
    RBP: 00007ffce72ad4d0   R8: 0000000000000000   R9: 0000000000000000
    R10: 0000000000000640  R11: 0000000000000202  R12: 00007ffce72ad201
    R13: 00007ffce72ad5c0  R14: 00007ffce72af19d  R15: 0000000000000000
    ORIG_RAX: 0000000000000052  CS: 0033  SS: 002b
```

```
crash> bt -t  147221
PID: 147221  TASK: ffff895d140d0000  CPU: 10  COMMAND: "mv"
              START: __schedule at ffffffff85ea4cc6
  [ffff9e33ab0af6c0] __schedule at ffffffff85ea4cc6
  [ffff9e33ab0af700] xfs_buf_find at ffffffffc0457435 [xfs]
  [ffff9e33ab0af720] schedule at ffffffff85ea5103
  [ffff9e33ab0af738] schedule_timeout at ffffffff85ea8a65
  [ffff9e33ab0af750] select_task_rq_fair at ffffffff854de761
  [ffff9e33ab0af798] xfs_buf_find at ffffffffc0457435 [xfs]
  [ffff9e33ab0af7b8] __down at ffffffff85ea7756
  [ffff9e33ab0af7d8] arch_haltpoll_enable.cold.25 at ffffffff85477200
  [ffff9e33ab0af810] down at ffffffff85500f91
  [ffff9e33ab0af830] xfs_buf_lock at ffffffffc0456fa7 [xfs]
  [ffff9e33ab0af858] xfs_buf_find at ffffffffc0457435 [xfs]
  [ffff9e33ab0af8e8] xfs_buf_get_map at ffffffffc0457743 [xfs]
  [ffff9e33ab0af938] xfs_buf_read_map at ffffffffc0457fab [xfs]
  [ffff9e33ab0af948] kmem_zone_alloc at ffffffffc047d34c [xfs]
  [ffff9e33ab0af980] xfs_trans_read_buf_map at ffffffffc04906e9 [xfs]
  [ffff9e33ab0af9c0] xfs_read_agi at ffffffffc0439783 [xfs]
  [ffff9e33ab0afa20] xfs_iunlink_remove at ffffffffc046d205 [xfs]
  [ffff9e33ab0afa48] _cond_resched at ffffffff85ea5399
  [ffff9e33ab0afaa0] xfs_rename at ffffffffc087f9e0 [livepatch_93597ae8]
  [ffff9e33ab0afb70] xfs_vn_rename at ffffffffc046a0b3 [xfs]
  [ffff9e33ab0afbe8] vfs_rename at ffffffff856e9955
  [ffff9e33ab0afc60] d_lookup at ffffffff856f88da
  [ffff9e33ab0afca0] ovl_do_rename at ffffffffc0d0e2bc [overlay]
  [ffff9e33ab0afce0] ovl_rename at ffffffffc0d0f557 [overlay]
  [ffff9e33ab0afd98] vfs_rename at ffffffff856e9955
  [ffff9e33ab0afe10] __lookup_hash at ffffffff856e6c94
  [ffff9e33ab0afe50] do_renameat2 at ffffffff856ed168
  [ffff9e33ab0aff20] __x64_sys_rename at ffffffff856ed3e0
  [ffff9e33ab0aff30] do_syscall_64 at ffffffff85404447
  [ffff9e33ab0aff50] entry_SYSCALL_64_after_hwframe at ffffffff8600008c
    RIP: 00007f85457cf367  RSP: 00007ffeb63a9778  RFLAGS: 00000206
    RAX: ffffffffffffffda  RBX: 0000000000008000  RCX: 00007f85457cf367
    RDX: 0000000000000000  RSI: 00007ffeb63ac1ad  RDI: 00007ffeb63ac1a0
    RBP: 00007ffeb63a9b40   R8: 0000000000000000   R9: 0000000000000000
    R10: 0000000000000640  R11: 0000000000000206  R12: 00007ffeb63a9901
    R13: 00007ffeb63a9c30  R14: 00007ffeb63ac1a0  R15: 0000000000000000
    ORIG_RAX: 0000000000000052  CS: 0033  SS: 002b
```

```
crash> bt -t 147220
PID: 147220  TASK: ffff8968e5305c40  CPU: 32  COMMAND: "mv"
              START: __schedule at ffffffff85ea4cc6
  [ffff9e33ab0cf6c0] __schedule at ffffffff85ea4cc6
  [ffff9e33ab0cf700] xfs_buf_find at ffffffffc0457435 [xfs]
  [ffff9e33ab0cf720] schedule at ffffffff85ea5103
  [ffff9e33ab0cf738] schedule_timeout at ffffffff85ea8a65
  [ffff9e33ab0cf750] select_task_rq_fair at ffffffff854de761
  [ffff9e33ab0cf798] xfs_buf_find at ffffffffc0457435 [xfs]
  [ffff9e33ab0cf7b8] __down at ffffffff85ea7756
  [ffff9e33ab0cf810] down at ffffffff85500f91
  [ffff9e33ab0cf830] xfs_buf_lock at ffffffffc0456fa7 [xfs]
  [ffff9e33ab0cf858] xfs_buf_find at ffffffffc0457435 [xfs]
  [ffff9e33ab0cf8e8] xfs_buf_get_map at ffffffffc0457743 [xfs]
  [ffff9e33ab0cf938] xfs_buf_read_map at ffffffffc0457fab [xfs]
  [ffff9e33ab0cf980] xfs_trans_read_buf_map at ffffffffc04906e9 [xfs]
  [ffff9e33ab0cf9c0] xfs_read_agi at ffffffffc0439783 [xfs]
  [ffff9e33ab0cfa20] xfs_iunlink at ffffffffc046ca7b [xfs]
  [ffff9e33ab0cfa30] current_time at ffffffff856f9921
  [ffff9e33ab0cfa80] xfs_droplink at ffffffffc046cc24 [xfs]
  [ffff9e33ab0cfaa0] xfs_rename at ffffffffc087fab2 [livepatch_93597ae8]
  [ffff9e33ab0cfb70] xfs_vn_rename at ffffffffc046a0b3 [xfs]
  [ffff9e33ab0cfbe8] vfs_rename at ffffffff856e9955
  [ffff9e33ab0cfc60] d_lookup at ffffffff856f88da
  [ffff9e33ab0cfca0] ovl_do_rename at ffffffffc0d0e2bc [overlay]
  [ffff9e33ab0cfce0] ovl_rename at ffffffffc0d0f557 [overlay]
  [ffff9e33ab0cfd98] vfs_rename at ffffffff856e9955
  [ffff9e33ab0cfe10] __lookup_hash at ffffffff856e6c94
  [ffff9e33ab0cfe50] do_renameat2 at ffffffff856ed168
  [ffff9e33ab0cff20] __x64_sys_rename at ffffffff856ed3e0
  [ffff9e33ab0cff30] do_syscall_64 at ffffffff85404447
  [ffff9e33ab0cff50] entry_SYSCALL_64_after_hwframe at ffffffff8600008c
    RIP: 00007f0c25917367  RSP: 00007fff15e5e8f8  RFLAGS: 00000202
    RAX: ffffffffffffffda  RBX: 0000000000008000  RCX: 00007f0c25917367
    RDX: 0000000000000000  RSI: 00007fff15e60c91  RDI: 00007fff15e60c77
    RBP: 00007fff15e5ecc0   R8: 0000000000000000   R9: 0000000000000000
    R10: 0000000000000640  R11: 0000000000000202  R12: 00007fff15e5ea01
    R13: 00007fff15e5edb0  R14: 00007fff15e60c77  R15: 0000000000000000
    ORIG_RAX: 0000000000000052  CS: 0033  SS: 002b
```

```
crash> bt -t 16429
PID: 16429  TASK: ffff896e77039ec0  CPU: 39  COMMAND: "runsv"
              START: __schedule at ffffffff85ea4cc6
  [ffff9e33961d74c0] __schedule at ffffffff85ea4cc6
  [ffff9e33961d7500] xfs_buf_find at ffffffffc0457435 [xfs]
  [ffff9e33961d7520] schedule at ffffffff85ea5103
  [ffff9e33961d7538] schedule_timeout at ffffffff85ea8a65
  [ffff9e33961d7550] _xfs_trans_bjoin at ffffffffc0490328 [xfs]
  [ffff9e33961d7578] xfs_trans_read_buf_map at ffffffffc0490729 [xfs]
  [ffff9e33961d7598] xfs_buf_find at ffffffffc0457435 [xfs]
  [ffff9e33961d75b8] __down at ffffffff85ea7756
  [ffff9e33961d75e0] xfs_btree_lookup_get_block at ffffffffc0420932 [xfs]
  [ffff9e33961d7608] down at ffffffff85500f91
  [ffff9e33961d7628] xfs_buf_lock at ffffffffc0456fa7 [xfs]
  [ffff9e33961d7650] xfs_buf_find at ffffffffc0457435 [xfs]
  [ffff9e33961d76e0] xfs_buf_get_map at ffffffffc0457743 [xfs]
  [ffff9e33961d7730] xfs_buf_read_map at ffffffffc0457fab [xfs]
  [ffff9e33961d7778] xfs_trans_read_buf_map at ffffffffc04906e9 [xfs]
  [ffff9e33961d77b8] xfs_read_agi at ffffffffc0439783 [xfs]
  [ffff9e33961d7818] xfs_ialloc_read_agi at ffffffffc0439854 [xfs]
  [ffff9e33961d7850] xfs_dialloc at ffffffffc043a163 [xfs]
  [ffff9e33961d78c8] xfs_ialloc at ffffffffc046b8ab [xfs]
  [ffff9e33961d7948] xfs_dir_ialloc at ffffffffc046e1b5 [xfs]
  [ffff9e33961d79e0] xfs_create at ffffffffc046e556 [xfs]
  [ffff9e33961d7a78] xfs_generic_create at ffffffffc046b4b6 [xfs]
  [ffff9e33961d7af8] xfs_vn_mknod at ffffffffc046b5a4 [xfs]
  [ffff9e33961d7b08] xfs_vn_create at ffffffffc046b5e3 [xfs]
  [ffff9e33961d7b18] vfs_create at ffffffff856ea530
  [ffff9e33961d7b58] ovl_create_real at ffffffffc0d0ebab [overlay]
  [ffff9e33961d7b88] ovl_create_or_link at ffffffffc0d0fe8e [overlay]
  [ffff9e33961d7bb8] inode_init_always at ffffffff856f8e11
  [ffff9e33961d7be0] alloc_inode at ffffffff856f9226
  [ffff9e33961d7c00] ovl_fill_inode at ffffffffc0d0b99c [overlay]
  [ffff9e33961d7c68] ovl_create_object at ffffffffc0d105bb [overlay]
  [ffff9e33961d7cb8] ovl_create at ffffffffc0d10683 [overlay]
  [ffff9e33961d7cc8] path_openat at ffffffff856ec08f
  [ffff9e33961d7da8] do_filp_open at ffffffff856ed9d3
  [ffff9e33961d7e58] __alloc_fd at ffffffff856fd596
  [ffff9e33961d7eb0] do_sys_open at ffffffff856d6aa8
  [ffff9e33961d7f20] __x64_sys_openat at ffffffff856d6c40
  [ffff9e33961d7f30] do_syscall_64 at ffffffff85404447
  [ffff9e33961d7f50] entry_SYSCALL_64_after_hwframe at ffffffff8600008c
    RIP: 00007f8986361c8e  RSP: 00007ffd58c71540  RFLAGS: 00000246
    RAX: ffffffffffffffda  RBX: 000055a4fc1c27fe  RCX: 00007f8986361c8e
    RDX: 0000000000000a41  RSI: 000055a4fc1c27d6  RDI: 00000000ffffff9c
    RBP: 000055a4fc1c2828   R8: 00007ffd58c71678   R9: 00007ffd58c71670
    R10: 00000000000001a4  R11: 0000000000000246  R12: 000055a4fc1c27d6
    R13: 000055a4fc1c2815  R14: 000055a4fc1c27ec  R15: 000055a4fc3c5100
    ORIG_RAX: 0000000000000101  CS: 0033  SS: 002b
```

```
crash> bt -t 2690
PID: 2690   TASK: ffff896e75769ec0  CPU: 10  COMMAND: "containerd"
              START: __schedule at ffffffff85ea4cc6
  [ffff9e334e3e7ae0] __schedule at ffffffff85ea4cc6
  [ffff9e334e3e7b40] schedule at ffffffff85ea5103
  [ffff9e334e3e7b58] rwsem_down_read_slowpath at ffffffff85ea7ed3
  [ffff9e334e3e7bb0] lookup_fast at ffffffff856e6f1c
  [ffff9e334e3e7bd8] xfs_ilock_data_map_shared at ffffffffc046d5b0 [xfs]
  [ffff9e334e3e7bf0] down_read at ffffffff85ea8125
  [ffff9e334e3e7c08] xfs_ilock at ffffffffc046d4d2 [xfs]
  [ffff9e334e3e7c28] xfs_dir_open at ffffffffc045c0a0 [xfs]
  [ffff9e334e3e7c38] xfs_ilock_data_map_shared at ffffffffc046d5b0 [xfs]
  [ffff9e334e3e7c50] xfs_dir_open at ffffffffc045c0d9 [xfs]
  [ffff9e334e3e7c70] xfs_dir_open at ffffffffc045c0a0 [xfs]
  [ffff9e334e3e7c80] do_dentry_open at ffffffff856d4e43
  [ffff9e334e3e7cb8] vfs_open at ffffffff856d678d
  [ffff9e334e3e7cc8] path_openat at ffffffff856eb119
  [ffff9e334e3e7cd8] filename_lookup at ffffffff856ed500
  [ffff9e334e3e7da8] do_filp_open at ffffffff856ed9d3
  [ffff9e334e3e7e58] __alloc_fd at ffffffff856fd596
  [ffff9e334e3e7eb0] do_sys_open at ffffffff856d6aa8
  [ffff9e334e3e7f20] __x64_sys_openat at ffffffff856d6c40
  [ffff9e334e3e7f30] do_syscall_64 at ffffffff85404447
  [ffff9e334e3e7f50] entry_SYSCALL_64_after_hwframe at ffffffff8600008c
    RIP: 00005580fc05c8da  RSP: 000000c422afb540  RFLAGS: 00000202
    RAX: ffffffffffffffda  RBX: 0000000000000000  RCX: 00005580fc05c8da
    RDX: 0000000000080000  RSI: 000000c423733bc0  RDI: ffffffffffffff9c
    RBP: 000000c422afb5c0   R8: 0000000000000000   R9: 0000000000000000
    R10: 0000000000000000  R11: 0000000000000202  R12: ffffffffffffffff
    R13: 000000000000004b  R14: 000000000000004a  R15: 0000000000000055
    ORIG_RAX: 0000000000000101  CS: 0033  SS: 002b
```

This version of [ubuntu kernel](https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/focal/tag/?h=Ubuntu-5.4.0-34.38) already have the patch:
[xfs: Fix deadlock between AGI and AGF with RENAME_WHITEOUT](https://lore.kernel.org/lkml/20200428182241.693131606@linuxfoundation.org/)
but not have
[xfs: Fix deadlock between AGI and AGF when target_ip exists in xfs_rename()](https://www.spinics.net/lists/linux-xfs/msg33879.html)
So we patched the second patch to our kernel, after some days, this issue still happens. 
From the stack, there is no AGF and AGI related lock stacks, so it should a different issue
with issues these two patches.

## Try to reproduce
Use following script to reproduce this issue
```
#!/bin/bash

SCRATCH_MNT=/mnt
LOAD_FACTOR=1
TIME_FACTOR=1

mkfs.xfs -f /dev/sda
mount /dev/sda $SCRATCH_MNT

mkdir $SCRATCH_MNT/lowerdir
mkdir $SCRATCH_MNT/lowerdir1
mkdir $SCRATCH_MNT/lowerdir/etc
mkdir $SCRATCH_MNT/workers
echo salts > $SCRATCH_MNT/lowerdir/etc/access.conf
touch $SCRATCH_MNT/running

stop_workers() {
test -e $SCRATCH_MNT/running || return
rm -f $SCRATCH_MNT/running

	while [ "$(ls $SCRATCH_MNT/workers/ | wc -l)" -gt 0 ]; do
		wait
	done
}

worker() {
local tag="$1"
local mergedir="$SCRATCH_MNT/merged$tag"
local l="lowerdir=$SCRATCH_MNT/lowerdir:$SCRATCH_MNT/lowerdir1"
local u="upperdir=$SCRATCH_MNT/upperdir$tag"
local w="workdir=$SCRATCH_MNT/workdir$tag"
local i="index=off"

	touch $SCRATCH_MNT/workers/$tag
	while test -e $SCRATCH_MNT/running; do
		rm -rf $SCRATCH_MNT/merged$tag
		rm -rf $SCRATCH_MNT/upperdir$tag
		rm -rf $SCRATCH_MNT/workdir$tag
		mkdir $SCRATCH_MNT/merged$tag
		mkdir $SCRATCH_MNT/workdir$tag
		mkdir $SCRATCH_MNT/upperdir$tag

		mount -t overlay overlay -o "$l,$u,$w,$i" $mergedir
		mv $mergedir/etc/access.conf $mergedir/etc/access.conf.bak
		touch $mergedir/etc/access.conf
		mv $mergedir/etc/access.conf $mergedir/etc/access.conf.bak
		touch $mergedir/etc/access.conf
		umount $mergedir
	done
	rm -f $SCRATCH_MNT/workers/$tag
}

for i in $(seq 0 $((4 + LOAD_FACTOR)) ); do
worker $i &
done

sleep $((30 * TIME_FACTOR))
stop_workers
```

Even in the newest kernel, this issue still can be reproduced

## Check the stack after issue reproduce
```
 crash> foreach UN ps -m|sort|tail
 [0 00:00:23.271] [UN]  PID: 38033  TASK: ffff908cd4c8ba80  CPU: 20
  COMMAND: "mv"
 [0 00:00:23.332] [UN]  PID: 38029  TASK: ffff908cd6093a80  CPU: 1
 COMMAND: "mv"
 [0 00:00:23.332] [UN]  PID: 38037  TASK: ffff908cd606ba80  CPU: 31
  COMMAND: "touch"
 [0 00:00:23.332] [UN]  PID: 38038  TASK: ffff908cd4c50000  CPU: 24
  COMMAND: "mv"
 [0 00:00:23.333] [UN]  PID: 38032  TASK: ffff908cd5a0ba80  CPU: 33
  COMMAND: "mv"
 [0 00:00:23.333] [UN]  PID: 38035  TASK: ffff908cd5110000  CPU: 8
 COMMAND: "touch"
 [0 00:00:23.336] [UN]  PID: 38040  TASK: ffff908cd4cbba80  CPU: 2
 COMMAND: "touch"
 [0 00:00:23.337] [UN]  PID: 38039  TASK: ffff908cd62cba80  CPU: 35
  COMMAND: "touch"
 [0 00:00:23.338] [UN]  PID: 38030  TASK: ffff908cdbfc0000  CPU: 15
  COMMAND: "mv"
 [0 00:00:23.339] [UN]  PID: 38036  TASK: ffff908cd4ce8000  CPU: 22
  COMMAND: "mv"
```

The `mv` process have the same stack like:

``` 
 crash> bt
 PID: 38029  TASK: ffff908cd6093a80  CPU: 1   COMMAND: "mv"
  #0 [ffffa848961b3558] __schedule at ffffffff8fa96c09
  #1 [ffffa848961b35e8] schedule at ffffffff8fa97235
  #2 [ffffa848961b3608] schedule_timeout at ffffffff8fa9ccc6
  #3 [ffffa848961b36c8] __down_common at ffffffff8fa9b2b3
  #4 [ffffa848961b3748] __down at ffffffff8fa9b311
  #5 [ffffa848961b3758] down at ffffffff8ed43be1
  #6 [ffffa848961b3778] xfs_buf_lock at ffffffffc06fab78 [xfs]
  #7 [ffffa848961b37a8] xfs_buf_find at ffffffffc06fb160 [xfs]
  #8 [ffffa848961b3850] xfs_buf_get_map at ffffffffc06fbf41 [xfs]
  #9 [ffffa848961b38a0] xfs_buf_read_map at ffffffffc06fcd67 [xfs]
  #10 [ffffa848961b38f0] xfs_trans_read_buf_map at ffffffffc0752496 [xfs]
  #11 [ffffa848961b3938] xfs_read_agi at ffffffffc06cdf02 [xfs]
  #12 [ffffa848961b39a0] xfs_iunlink at ffffffffc071c741 [xfs]
  #13 [ffffa848961b3a08] xfs_droplink at ffffffffc071c9e2 [xfs]
  #14 [ffffa848961b3a30] xfs_rename at ffffffffc07221b7 [xfs]
  #15 [ffffa848961b3b08] xfs_vn_rename at ffffffffc0717ec4 [xfs]
  #16 [ffffa848961b3b80] vfs_rename at ffffffff8eff9d65
  #17 [ffffa848961b3c40] ovl_do_rename at ffffffffc091d177 [overlay]
  #18 [ffffa848961b3c78] ovl_rename at ffffffffc091e885 [overlay]
  #19 [ffffa848961b3d10] vfs_rename at ffffffff8eff9d65
  #20 [ffffa848961b3dd8] do_renameat2 at ffffffff8effcc66
  #21 [ffffa848961b3ea8] __x64_sys_rename at ffffffff8effcdb9
  #22 [ffffa848961b3ec0] do_syscall_64 at ffffffff8ec04c54
  #23 [ffffa848961b3f50] entry_SYSCALL_64_after_hwframe at ffffffff8fc00091
     RIP: 00007f84ed829da7  RSP: 00007ffe6da90508  RFLAGS: 00000202
     RAX: ffffffffffffffda  RBX: 00007ffe6da9093f  RCX: 00007f84ed829da7
     RDX: 0000000000000000  RSI: 00007ffe6da92b94  RDI: 00007ffe6da92b7a
     RBP: 00007ffe6da908e0   R8: 0000000000000001   R9: 0000000000000000
     R10: 0000000000000001  R11: 0000000000000202  R12: 00007ffe6da909c0
     R13: 0000000000000000  R14: 0000000000000000  R15: 00007ffe6da92b7a
     ORIG_RAX: 0000000000000052  CS: 0033  SS: 002b
```

## Check for who hold the lock

From the stack and lock's defination, I can't find which process hold this lock, so revert the pr:
[xfs: remove b_last_holder & associated macros](https://github.com/torvalds/linux/commit/fa6c668d807b1e9ac041101dfcb59bd8e279cfe5)
This can help to debug

* Check for process 38036

```
 crash> set 38036
     PID: 38036
 COMMAND: "mv"
    TASK: ffff908cd4ce8000  [THREAD_INFO: ffff908cd4ce8000]
     CPU: 22
   STATE: TASK_UNINTERRUPTIBLE


 It is waiting for a lock, which is holding by 38029:

 crash> struct xfs_buf.b_last_holder ffff908f92a0a680
   b_last_holder = 38029
```

* Check for process 38029
```
crash> set 38029
          PID: 38029
      COMMAND: "mv"
         TASK: ffff908cd6093a80  [THREAD_INFO: ffff908cd6093a80]
          CPU: 1
        STATE: TASK_UNINTERRUPTIBLE

 crash> struct xfs_buf.b_last_holder ffff908f993cc780
   b_last_holder = 38030

 It is waiting for a lock, which is holding  by 38030

```

* Check for process 38030
```
 crash> set 38030
          PID: 38030
      COMMAND: "mv"
         TASK: ffff908cdbfc0000  [THREAD_INFO: ffff908cdbfc0000]
          CPU: 15
        STATE: TASK_UNINTERRUPTIBLE

 crash> struct xfs_buf.b_last_holder ffff908f92a0a680
   b_last_holder = 38029
```

## Check for where to get the lock
Use a simple ebpf tools
[xfs lock trace script](/assets/xfs.py)
to print the stacks when the acquire/free the lock

Lock ffff908f92a0a680 should be held by 38029 in xfs_iunlink_remove() but not released:

```
>   b'xfs_buf_trylock+0x1'
>   b'xfs_buf_get_map+0x51'
>   b'xfs_buf_read_map+0x47'
>   b'xfs_trans_read_buf_map+0xf6'
>   b'xfs_read_agi+0xd2'
>   b'xfs_iunlink_remove+0x9a'
>   b'xfs_rename+0x618'
>   b'xfs_vn_rename+0x104'
>   b'vfs_rename+0x6e5'
>   b'ovl_do_rename+0x47'
>   b'ovl_rename+0x5d5'
>   b'vfs_rename+0x6e5'
>   b'do_renameat2+0x576'
>   b'__x64_sys_rename+0x29'
>   b'do_syscall_64+0x84'
>   b'entry_SYSCALL_64_after_hwframe+0x49'
```

```
>   b'xfs_buf_trylock+0x1'
>   b'xfs_buf_get_map+0x51'
>   b'xfs_buf_read_map+0x47'
>   b'xfs_trans_read_buf_map+0xf6'
>   b'xfs_read_agi+0xd2'
>   b'xfs_iunlink_remove+0x9a'
>   b'xfs_rename+0x618'
>   b'xfs_vn_rename+0x104'
>   b'vfs_rename+0x6e5'
>   b'ovl_do_rename+0x47'
>   b'ovl_rename+0x5d5'
>   b'vfs_rename+0x6e5'
>   b'do_renameat2+0x576'
>   b'__x64_sys_rename+0x29'
>   b'do_syscall_64+0x84'
>   b'entry_SYSCALL_64_after_hwframe+0x49'
```


 The lock 0xffff908f993cc780 should also be held by 38030
  xfs_iunlink_remove() but not released:

```
>   b'xfs_buf_trylock+0x1'
>   b'xfs_buf_get_map+0x51'
>   b'xfs_buf_read_map+0x47'
>   b'xfs_trans_read_buf_map+0xf6'
>   b'xfs_read_agi+0xd2'
>   b'xfs_iunlink_remove+0x9a'
>   b'xfs_rename+0x618'
>   b'xfs_vn_rename+0x104'
>   b'vfs_rename+0x6e5'
>   b'ovl_do_rename+0x47'
>   b'ovl_rename+0x5d5'
>   b'vfs_rename+0x6e5'
>   b'do_renameat2+0x576'
>   b'__x64_sys_rename+0x29'
>   b'do_syscall_64+0x84'
>   b'entry_SYSCALL_64_after_hwframe+0x49'

```

Looks like there are ABBA deadlock in this scenario.
 
## report this issue to the maintainer and get the fix

Details: https://www.spinics.net/lists/linux-xfs/msg47556.html 