---
layout: post
tags: storage disk
title: Disk usage high in container
categories: Linux container
date: 2020-04-15 14:02:32-0700
excerpt: disk usage high in container
---

## Issue 
User reported that there disk had been used up.

```
2020.04.15 17:34:04:920 [main] ERROR c.e.f.i.s.n.h.HBaseNRTBuilder.buildUsecase:140 - Failed to build NRT index for usecase item_active
java.io.IOException: Disk quota exceeded
	at java.io.UnixFileSystem.createFileExclusively(Native Method)
	at java.io.File.createTempFile(File.java:2026)

```

But he checked the volume by du and find it is only 148M files
```
root@active-stream-1-7755cff88-vhrww:/opt$ du -sh docker/
148M	docker/
```
## Check for what happend
We limit the emptydir with xfs_quota feature, so that user can only use 2Gi of emptyDir, 
so if run `df` , then it will show the disk usage is 100%

```
Filesystem                Size      Used Available Use% Mounted on
/dev/sdc4                 2G        2G     4.0K 100% /opt
```

## root cause

As we know, if the files that process open() but not close() after the file delete, then we can see
du and df can have this kind of behavior.

So we can use following commands to check for this:
* `lsof|grep deleted`
* `ls -lah /proc/[1-9]*/fd|grep delete` and `cat /proc/[1-9]* /maps|grep delete`

Ref: 
* [du-vs-df](https://www.redhat.com/sysadmin/du-vs-df)
* [why-du-and-df-display-different-values](http://linuxshellaccount.blogspot.com/2008/12/why-du-and-df-display-different-values.html) 