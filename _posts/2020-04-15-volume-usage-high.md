---
layout: post
tags: disk linux volume
title: Disk usage high in container
categories: Linux
date: 2020-04-15 14:02:32-0700
excerpt: disk usage high in container
---

## Issue 
User reported that there disk had been used up.

```
2020.03.15 17:34:04:920 [main] ERROR c.e.f.i.s.n.h.HBaseNRTBuilder.buildUsecase:140 - Failed to build NRT index for usecase item_active
java.io.IOException: Disk quota exceeded
	at java.io.UnixFileSystem.createFileExclusively(Native Method)
	at java.io.File.createTempFile(File.java:2026)

```

But he checked the volume by du and find there is only 148M files
```
root@active-stream-1-7755cff88-vhrww:/opt$ du -sh docker/
148M	docker/
```
## Check for what happend

We limit the pod's emptydir with xfs_quota feature, user can only use 2Gi of emptyDir, 
If run `df` , it will show that volume's disk usage is 100%

```
Filesystem                Size      Used Available Use% Mounted on
/dev/sdc4                 2G        2G     4.0K 100% /opt
```

## root cause

As we know, if the files that process use open() to open it but not call close() to close the fd after the file delete, 
then du and df commands have this kind of behavior.

So following commands can be used to check for this:
* `lsof|grep deleted`
* `ls -lah /proc/[1-9]*/fd|grep delete` and `cat /proc/[1-9]* /maps|grep delete`

Ref: 
* [du-vs-df](https://www.redhat.com/sysadmin/du-vs-df)
* [why-du-and-df-display-different-values](http://linuxshellaccount.blogspot.com/2008/12/why-du-and-df-display-different-values.html) 
