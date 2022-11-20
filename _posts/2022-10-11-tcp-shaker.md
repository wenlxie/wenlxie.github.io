---
layout: post
tags: eBPF linux
title: tcp-shaker
categories: Network
date: 2022-10-11 14:02:32-0700
excerpt: tcp-shaker
---

## Issues

<<<<<<< HEAD
Recently we met an issue that related with tcp healthy check. 
Our software load balancer need to do health check with backend VIP (DSR mode, so need to check for the VIP) periodically via TCP.
Since it needs to specific the source IP for the connection, so it will do bind() operation, but sometimes it met the error of "bind: address already in use"
. 
This is caused by the ip source port exhausted, lots of health check connections are in TIME_WAIT status and not release the source port.  
=======
Recently we met an issue that related with tcp healthy check.
Our software load balancer need to do health check with backend VIP (DSR mode, so need to check for the VIP) periodically via TCP.
Since it needs to specific the source IP for the connection, so it will do bind() operation, but sometimes it met the error of "bind: address already in use"
.
This is caused by the ip source port exhausted, lots of health check connections are in TIME_WAIT status and not release the source port.
>>>>>>> 8977dff (Add kretprobe)

## tcp-shaker

We need to make the source port to be released quickly.

One solution is:
- We sent tcp syn request with a port server not listen, and then server will reply with an RST packet.

Another solution is use [tcp-shaker](https://github.com/tevino/tcp-shaker)

## Implementation of tcp-shaker

* Readme

```
In most cases when you establish a TCP connection(e.g. via net.Dial), these are the first three packets between the client and server(TCP three-way handshake):

Client -> Server: SYN
Server -> Client: SYN-ACK
Client -> Server: ACK
This package tries to avoid the last ACK when doing handshakes.

By sending the last ACK, the connection is considered established.

However, as for TCP health checking the server could be considered alive right after it sends back SYN-ACK,

that renders the last ACK unnecessary or even harmful in some cases.

```

* tcp-shaker acheived this by set the socket with option

- SO_LINGER with timeout=0  

- https://github.com/tevino/tcp-shaker/blob/master/socket_linux.go#L60

- Disable TCP_QUICKACK

  https://github.com/tevino/tcp-shaker/blob/master/socket_linux.go#L53

Disable the QuickAck makes the last ack in tcp handshake to be hold and not sent immediately.
The max hold time is 200ms ( HZ/5 in code) in Linux

SO_LINGER with timeout=0 makes the close() (https://github.com/tevino/tcp-shaker/blob/master/checker_linux.go#L154)
sent out RST to finish the connection instead of FIN.

Ref: https://stackoverflow.com/questions/3757289/when-is-tcp-option-so-linger-0-required

This is a smart solution for handshake.

- In client side, the socket can be closed quickly, no need kept in TIME_WAIT status, so source port can be released quickly

- In server side, the socket is not in ESTABLISHED status since tcp handshake not finished, so it will not impact the application, which is calling accept().

- If the RST not received by server, server's socket will retry to sent out synack to client, then what will client do?
  From the source code, there will be no socket find for this request, so client will send a RST to server again.

- In client, the source port can be reused, so it may use this source port and sent syn request to server, but if server is still in TCP_SYN_RECV status because of RST lost, then what will happen for this request?
  From the tcpdump, there will be an ack packet from server, and then client will do reset.

```
08:53:41.175810 IP 10.aa.bb.63.48528 > 10.9.yy.xx.10250: Flags [S], seq 3212740630, win 64240, options [mss 1460,sackOK,TS val 4150202543 ecr 0,nop,wscale 7], length 0
08:53:41.183790 IP 10.9.yy.xx.10250 > 10.aa.bb.63.48528: Flags [.], ack 1, win 509, options [nop,nop,TS val 4102712572 ecr 4150189740], length 0
08:53:41.183824 IP 10.aa.bb.63.48528 > 10.9.yy.xx.10250: Flags [R], seq 3012700204, win 0, length 0
```
So disable TCP_QUICKACK is a key step, which can handle the situation when RST packet lost

