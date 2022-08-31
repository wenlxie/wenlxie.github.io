---
layout: post
tags: traceroute
title: traceroute to debug network issue
categories: Network
date: 2020-03-02 14:02:32-0700
excerpt: traceroute
---

traceroute is a useful tools that can be used to debug network issues like route error or duplicated IP  

### DNS takes more than 5s sometimes inside user's pods

User reports that they have dns issue inside their pod

* Run command like dig or hostname, which can trigger the dns query, sometimes it takes more than 5s inside the pod
* If run dig or hostname commands in the host, then we can't see this issue
* Do tcpdump of the dns related packet, we can see that the dns query request packet sent out but no dns response received.
* So there is something wrong for route the packets to the pod, we can use traceroute to check this.

```
[root@tclient-3956578 env]# traceroute  10.10.10.10
traceroute to  10.10.10.10 (10.10.10.10), 30 hops max, 60 byte packets

1  ********************************
2  ********************************
3  ********************************
4  ********************************
5  ********************************
6  ********************************
7  ********************************
8  ********************************
9  ********************************
10 ********************************
11 ********************************
12  rxx03-ryy027-int-0-0-29.xxx.com (10.20.20.20)  15.009 ms rxx03-ryy018-int-0-0-31.xxx.com (10.20.20.30)  19.962 ms rxx03-ryy018-int-0-0-30.xxx.com (10.20.20.40)  19.506 ms
13  xxxx-node-yyyy-tttt.xxx.com (10.20.50.50)  12.104 ms *  12.078 ms
14  xxxx-yyyy--pod.xxx.com (10.10.10.10)  12.235 ms  12.538 ms *

```

The route to host  `xxxx-node-yyyy-tttt.xxx.com` go through ryy027 and ryy018, but node is supposed  to be under ryy018 but not ryy027, 
so the packet will be lost when it go through TOR ryy027, the root cause is subnet enabled in both ryy018 and ryy027

```
xxx@rxx03-ryy018> show configuration | display set | match 10.20.50.
set interfaces irb unit 0 family inet address 10.20.50.1/24
set protocols bgp group LEAF_TO_HOSTS_V4 allow 10.20.50.0/24

xxx@rxx03-ryy027> show configuration | display set | match 10.20.50.
set interfaces irb unit 0 family inet address 10.20.50.1/24
set protocols bgp group LEAF_TO_HOSTS_V4 allow 10.20.50.0/24

```

## Port can be reachable in local pod but not reachable in other pod

User reported the listen port can be access inside their pod, but not reachable in other pod

* There should be issues route packet to user's pod, so let's do traceroute to check for it

```
1   xxxxxxxxxxxxxxxxxxx
2   xxxxxxxxxxxxxxxxxxx
3   xxxxxxxxxxxxxxxxxxx
4   xxxxxxxxxxxxxxxxxxx
5   xxxxxxxxxxxxxxxxxxx
6   xxxxxxxxxxxxxxxxxxx
7   xxxxxxxxxxxxxxxxxxx
8   xxxxxxxxxxxxxxxxxxx
9   xxxxxxxxxxxxxxxxxxx
10  xxxxxxxxxxxxxxxxxxx
11  xxxxxxxxxxxxxxxxxxx
12  zzz-0-0-29-rxx06-ryyy.xxxx.com (10.20.20.20)  21.133 ms zzz-0-0-31-rxx06-ryyy025.xxxx.com (10.20.20.21)  24.703 ms zzz-0-0-30-rxx06-ryyy025.xxxx.com (10.20.20.22)  24.650 ms
13  10.30.30.30 (10.30.30.30)  10.810 ms 
```

* The pod ip should be access through the node, so the hop before the pod should be the node, but we can see that pod can be accessed directly through tor.
* Check for the TOR to get the interface of the device connected with this IP

```
{master:0}
xxxxx@rxx06-ryyy> show arp | match xe-0/0/0:0
74:db:d1:80:d2:9e 10.30.30.30     10.30.30.30               irb.0 [xe-0/0/0:0.0]    none
74:db:d1:80:b4:b4 10.30.30.40     10.30.30.40                irb.0 [xe-0/0/0:0.0]    none
```

* 10.30.30.40 is a Hypervisor, after login to it, there is a VM with IP 10.30.30.30.





