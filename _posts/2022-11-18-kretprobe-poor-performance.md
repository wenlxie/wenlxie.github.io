---
layout: post
tags: kretprobe kprobe eBPF ftrace
title: kretprobe poor performance
categories: Linux
date: 2020-11-18 14:02:32-0700
excerpt: kretprobe poor performance
---

## Issue 

Recently I met an kretporbe performance issue on our prod environment. 

We want to use kretprobe to hook for function ipt_do_table() in kernel to get the return value, which is a 
verdict to indicate whether the packet be ACCEPT, DROP or STOLEN by iptables.

But after the eBPF program deployed, some of the nodes has high SI usage. 

```
%Cpu(s): 11.8 us,  4.7 sy,  0.0 ni, 49.3 id,  0.0 wa,  0.0 hi, 34.2 si,  0.0 st
MiB Mem : 385361.6 total, 212019.8 free, 122891.7 used,  50450.0 buff/cache
MiB Swap:      0.0 total,      0.0 free,      0.0 used. 260467.6 avail Mem 
```

Ping latency can up to 100ms sometimes

## Check for what CPU is busy for

From the flame graph, we can see that the CPU is busy handing the kretprobe hooks. 

![](/assets/2022-11-18-kretprobe.png)

We are using ubuntu 20.04 and which is 5.4.0 kernel.

In function pre_handler_kretprobe(), it will 
- get a free instance, and bind the instance with the current task 
- execute the handler and then free the instance. 
- call arch_prepare_kretprobe to replace the return value in reg.

```
/*
 * This kprobe pre_handler is registered with every kretprobe. When probe
 * hits it will set up the return probe.
 */
static int pre_handler_kretprobe(struct kprobe *p, struct pt_regs *regs)
{
	struct kretprobe *rp = container_of(p, struct kretprobe, kp);
	unsigned long hash, flags = 0;
	struct kretprobe_instance *ri;

	/*
	 * To avoid deadlocks, prohibit return probing in NMI contexts,
	 * just skip the probe and increase the (inexact) 'nmissed'
	 * statistical counter, so that the user is informed that
	 * something happened:
	 */
	if (unlikely(in_nmi())) {
		rp->nmissed++;
		return 0;
	}

	/* TODO: consider to only swap the RA after the last pre_handler fired */
	hash = hash_ptr(current, KPROBE_HASH_BITS);
	raw_spin_lock_irqsave(&rp->lock, flags);
	if (!hlist_empty(&rp->free_instances)) {
		ri = hlist_entry(rp->free_instances.first,
				struct kretprobe_instance, hlist);
		hlist_del(&ri->hlist);
		raw_spin_unlock_irqrestore(&rp->lock, flags);

		ri->rp = rp;
		ri->task = current;

		if (rp->entry_handler && rp->entry_handler(ri, regs)) {
			raw_spin_lock_irqsave(&rp->lock, flags);
			hlist_add_head(&ri->hlist, &rp->free_instances);
			raw_spin_unlock_irqrestore(&rp->lock, flags);
			return 0;
		}

		arch_prepare_kretprobe(ri, regs);

		/* XXX(hch): why is there no hlist_move_head? */
		INIT_HLIST_NODE(&ri->hlist);
		kretprobe_table_lock(hash, &flags);
		hlist_add_head(&ri->hlist, &kretprobe_inst_table[hash]);
		kretprobe_table_unlock(hash, &flags);
	} else {
		rp->nmissed++;
		raw_spin_unlock_irqrestore(&rp->lock, flags);
	}
	return 0;
}
NOKPROBE_SYMBOL(pre_handler_kretprobe);

```

There are raw_spin_lock_irqsave called to acquire lock for rp->lock, which is a gloabl lock for that retprobe.

That should be the reason for why it has poor performance. 


## Improvement 
Checked for 5.15 kernel, the implementation for the list and been changed to be lockless. 
```
/*
 * This kprobe pre_handler is registered with every kretprobe. When probe
 * hits it will set up the return probe.
 */
static int pre_handler_kretprobe(struct kprobe *p, struct pt_regs *regs)
{
	struct kretprobe *rp = container_of(p, struct kretprobe, kp);
	struct kretprobe_instance *ri;
	struct freelist_node *fn;

	fn = freelist_try_get(&rp->freelist);
	if (!fn) {
		rp->nmissed++;
		return 0;
	}

	ri = container_of(fn, struct kretprobe_instance, freelist);

	if (rp->entry_handler && rp->entry_handler(ri, regs)) {
		freelist_add(&ri->freelist, &rp->freelist);
		return 0;
	}

	arch_prepare_kretprobe(ri, regs);

	__llist_add(&ri->llist, &current->kretprobe_instances);

	return 0;
}
NOKPROBE_SYMBOL(pre_handler_kretprobe);

```

## solution
- Upgrade kernel to make fexit() supported, and use fexit() instead of kretprobe()
- Add a tracepoint to the ipt_do_table function, then use raw_tracepoint instead of kretprobe
  After load test. Compare with kreprobe/kprobe, raw_tp and tp perroamnce are much more better.
