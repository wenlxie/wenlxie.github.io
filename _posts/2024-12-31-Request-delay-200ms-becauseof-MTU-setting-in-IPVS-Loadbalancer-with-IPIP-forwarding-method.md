---
layout: post
tags: IPVS IPIP ICMP LINUX
tile: Request delay 200ms+ because of MTU setting in IPVS Loadbalancer with IPIP forwarding method
categories: Network
date: 2024-12-31 14:02:32-0700
excerpt: IPVS IPIP ICMP LINUX
---


## Backgroud

In our network environment, we use IPVS as a load balancer to provide virtual services and the IPIP protocol to preserve client IPs. The traffic flow is as follows:


![](/assets/2024-12-31-IPVS-IPIP-FLOW.png)



The client pod has envoy sidecar injected. 

Recently we have some customers that reported  their request has a high timeout rate after they move to this network flow.


- The client create a new request to VIP 10.0.0.2:443 with client IP 10.0.0.1 and port 12345 (Use  12345 as an example)
  The connection is 10.0.0.1:12345 → 10.0.0.2:443

- Iptables rules intercept the request and redirect the traffic to port 15001, changing the connection's destination IP and port to 127.0.0.1 and 15006. The connection now is 10.0.0.1:12345 → 127.0.0.1:15001.

- The client sidecar Envoy receives the request from the lo interface. Since outbound traffic is passthrough, Envoy does not perform any checks at the HTTP/HTTPS layer and creates a new connection to destination 10.0.0.2. The request is forwarded to VIP 10.0.0.2 with the connection 10.0.0.1:54321 → 10.0.0.2:443.

- The load balancer uses IPVS with the IPIP packet forwarding method and has the following IPVS rule:

```
ipvsadm -Ln -t 10.0.0.2:443
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port           Forward Weight ActiveConn InActConn
TCP  10.0.0.2:443 mh
  -> 10.0.0.6:443                 Tunnel    1      0          0         
  -> 10.0.0.7:443                 Tunnel    1      0          0         
  -> 10.0.0.8:443                 Tunnel    1      0          0
```

- The request is forwarded to a real server with an IPIP tunnel header, where the outer IP header has source IP 10.0.0.5 (load balancer's IP) and destination IP 10.0.0.6 (real server's IP), while the inner IP/TCP header remains unchanged.


- After receiving the request, the real server strips the outer IP header, processes the request, and sends a response directly to the client, bypassing the load balancer.

The sidecar(envoy) in the client side and Loadbalancer only handles the request in the TCP layer, so the TLS and HTTP interaction happens between the client and server directly. 


## Tcpdump Analysis

After TCPDUMP for the request to check for why the request was delayed. 
Here is the dump result:

![](/assets/2024-12-31-TCPDUMP-request-B.png)


This is the tcpdump file captured from lo and eth0 interface in the client side.

-  No 257571 to 257797 packets are the TCP and TLS handshake packets.
-  The No 257858 packet is the packet sent from the client and received in the lo interface.
-  Instead of forwarding this packet to 10.0.0.2 directly,  there are 4 ICMP packets with the source IP 10.0.0.1 and destination IP 10.0.0.1 captured.
   The details of this ICMP packet:

  ![](/assets/2024-12-31-ICMP-type3-code4.png) 

-  The No 259044 packet is the first packet sent from 10.0.0.1 to 10.0.0.2. The timestamp is 09:05:53.638466, which is about 207.76 ms delay compared with  09:05:53.430710  (No 257858 packet)

But the weird thing is, there was another request almost at the same time, but have different behavior 

![](/assets/2024-12-31-TCPDUMP-request-A.png)


-  No 257563 to 257776 packets are the TCP and TLS handshake packets
-  The No 257809 packet is the packet sent from the client and received in the lo interface. 
-  Then No 257812 packet is the packet that passthrough the No 257809 packet to 10.0.0.2 
-  Then a destination unreachable ICMP packet received with source IP 10.0.0.2 to client 10.0.0.1 (No 257815 Packet)
-  No 257819 Packet is the retransmission packet of No 257812 with only 09:05:53.430290 - 09:05:53.430181 = 0.1 ms

This request (request A in the following content) is a bit earlier  than the previous request (request B in the following content) which has issues. So it looks like the No 257815 Packet triggered something in the TCP stack and finally  made the 200ms delay.


## ICMP destination unreachable packet

This error message occurs when the size of a packet is larger than the MTU of the interface that needs to route it.  Since IPVS will add an extra IP header (IPIP tunnel), it will add 20 bytes to the original packet, which will change the packet length, and then if the packet is marked with DF (don’t frag), then it will send the ICMP destination unreachable packet to the client. 


https://elixir.bootlin.com/linux/v5.15.126/source/net/netfilter/ipvs/ip_vs_xmit.c#L239-L249

```
static inline bool ensure_mtu_is_adequate(struct netns_ipvs *ipvs, int skb_af,
					  int rt_mode,
					  struct ip_vs_iphdr *ipvsh,
					  struct sk_buff *skb, int mtu)
{
#ifdef CONFIG_IP_VS_IPV6
	if (skb_af == AF_INET6) {
		struct net *net = ipvs->net;

		if (unlikely(__mtu_check_toobig_v6(skb, mtu))) {
			if (!skb->dev)
				skb->dev = net->loopback_dev;
			/* only send ICMP too big on first fragment */
			if (!ipvsh->fragoffs && !ip_vs_iph_icmp(ipvsh))
				icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu);
			IP_VS_DBG(1, "frag needed for %pI6c\n",
				  &ipv6_hdr(skb)->saddr);
			return false;
		}
	} else
#endif
	{
		/* If we're going to tunnel the packet and pmtu discovery
		 * is disabled, we'll just fragment it anyway
		 */
		if ((rt_mode & IP_VS_RT_MODE_TUNNEL) && !sysctl_pmtu_disc(ipvs))
			return true;

		if (unlikely(ip_hdr(skb)->frag_off & htons(IP_DF) &&
			     skb->len > mtu && !skb_is_gso(skb) &&
			     !ip_vs_iph_icmp(ipvsh))) {
			icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
				  htonl(mtu));
			IP_VS_DBG(1, "frag needed for %pI4\n",
				  &ip_hdr(skb)->saddr);
			return false;
		}
	}

	return true;
}

```

From the details of this ICMP packet, it also contains the MTU information, which is 1480.

 ![](/assets/2024-12-31-ICMP-type3-code4.png)

The MTU setting is 1500 in any of the hop the whole traffic flow.  IPIP tunnels need to have another IP header injected, which is 20 bytes, that is why IPVS ask the client to send packets based on MTU 1480. 

So if we change the interface’s MTU or route MTU to be 1480 in the client or server side, then this issue can be resolved. But there are still something that  not resolved:



## Question 1: How does the ICMP destination unreachable packet impact the client behavior?

Let is check for the source code for how to handle the ICMP destination unreachable packet (FRAG NEEDED)  packets  in Linux

https://elixir.bootlin.com/linux/v5.15.126/source/net/ipv4/tcp_ipv4.c#L545-L561

After receive the ICMP unreachable packet,  https://elixir.bootlin.com/linux/v5.15.126/source/net/ipv4/icmp.c#L858 
Then it will start to change MTU by icmp_socket_deliver() →tcp_v4_err()

```
	if (code == ICMP_FRAG_NEEDED) { /* PMTU discovery (RFC1191) */

			/* We are not interested in TCP_LISTEN and open_requests

			 * (SYN-ACKs send out by Linux are always <576bytes so

			 * they should go through unfragmented).

			 */

			if (sk->sk_state == TCP_LISTEN)

				goto out;



			WRITE_ONCE(tp->mtu_info, info);

			if (!sock_owned_by_user(sk)) {

				tcp_v4_mtu_reduced(sk);

			} else {

				if (!test_and_set_bit(TCP_MTU_REDUCED_DEFERRED, &sk->sk_tsq_flags))

					sock_hold(sk);

			}

			goto out;

		}
```

If the sock is not held by user, then it will reduce the MTU directly by tcp_v4_mtu_reduced()
But if the the tcp socket is held by user, then it will set TCP small queue flags TCP_MTU_REDUCED_DEFERRED, after socket released by userspace, tcp_release_cb() will be called to handle for the tsq, and tcp_v4_mtu_reduced() will be called. 

https://elixir.bootlin.com/linux/v5.15.126/source/net/ipv4/tcp_output.c#L1112-L1115
So after the ICMP packet has been handled, the route MTU will be changed to 1480 and linux kernel will keep this MTU cache for 600s.


```
ip route get 10.0.0.2

10.0.0.2 via 10.x.x.x dev eth0 src 10.0.0.1 uid 0 
    cache 421
```

```
net.ipv4.route.mtu_expires = 600
net.ipv6.route.mtu_expires = 600
```



## Question 2:   Why there are multiple ICMP destination unreachable packet (FRAG NEEDED)  packets with the source IP = destination IP



Let’s trace the kernel stack of function icmp_send((skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu)) 
icmp_send() is the function in the Linux kernel that sends this ICMP packet, by tracing it, we can see how this  is  triggered?


```
        __icmp_send
        __ip_finish_output
        ip_finish_output
        ip_output
        ip_local_out
        __ip_queue_xmit
        ip_queue_xmit
        __tcp_transmit_skb
        tcp_write_xmit
        __tcp_push_pending_frames
        tcp_push
        tcp_sendmsg_locked
        tcp_sendmsg
        inet_sendmsg
        sock_sendmsg
        sock_write_iter
        do_iter_readv_writev
        do_iter_write
        vfs_writev
        do_writev
        __x64_sys_writev
        do_syscall_64
        entry_SYSCALL_64_after_hwframe

```

From the call stack, we can see that It checks the route MTU and tries to IP fragment, if DF bit is set in the IP header, then kernel will send the ICMP packet with type: 3 (ICMP_DEST_UNREACH) and code: 4 (ICMP_FRAG_NEEDED).

There were two requests almost at the same time. The first request will trigger the ICMP destination unreachable packet from the load balancer, and then it will change the route MTU to be 1480. Then the second request, which do the MSS negotiation based on MTU 1500 and but  route MTU had been changed to 1480 on the fly,  so when the packet length > 1500, then ICMP packet with type: 3 (ICMP_DEST_UNREACH) and code: 4 (ICMP_FRAG_NEEDED)  will be sent in kernel with the source IP == destination IP.

If we check for the statistics in linux kernel by netstat,  we can see that there are some statistics for this.

```
Icmp:
    6957 ICMP messages received
    22 input ICMP message failed
    ICMP input histogram:
        destination unreachable: 6940
        timeout in transit: 17
    3601 ICMP messages sent
    0 ICMP messages failed
    ICMP output histogram:
        destination unreachable: 65
        time exceeded: 3536
```

The destination unreachable: 6940 in ICMP input histogram is for the statistics when receiving the ICMP type: 3 (ICMP_DEST_UNREACH) and code: 4 (ICMP_FRAG_NEEDED), basically for the case like request A.  
The destination unreachable: 65 in ICMP output histogram is for the statistics when sending  the ICMP type: 3 (ICMP_DEST_UNREACH) and code: 4 (ICMP_FRAG_NEEDED), basically for the case like request A.  



## Question 3: Why does the ICMP packet not trigger the tcp retransmission?



In  Question 1, we have the details for how the Linux kernel handles the ICMP packet with type: 3 (ICMP_DEST_UNREACH) and code: 4 (ICMP_FRAG_NEEDED). 
It can be handled in tcp_v4_mtu_reduced(struct sock *sk)

https://elixir.bootlin.com/linux/v5.15.126/source/net/ipv4/tcp_ipv4.c#L555
https://elixir.bootlin.com/linux/v5.15.126/source/net/ipv4/tcp_ipv4.c#L341-L374

OR
tcp_tsq_write(struct sock *sk)
https://elixir.bootlin.com/linux/v5.15.126/source/net/ipv4/tcp_ipv4.c#L557
https://elixir.bootlin.com/linux/v5.15.126/source/net/ipv4/tcp_output.c#L1025
https://elixir.bootlin.com/linux/v5.15.126/source/net/ipv4/tcp_output.c#L1014-L1020

This is based on the held status of the socket 
https://elixir.bootlin.com/linux/v5.15.126/source/net/ipv4/tcp_ipv4.c#L554


From the tcpdump, the request A has the tcp retransmission triggered and it helps for the delay duration. But request B doesn't have  tcp retransmission triggered, and it is being delayed for more than 200ms. 

So we need to check for  how the ICMP packet was handled which was triggered by request B and why it was delayed for more than 200ms. 

Check for how this ICMP packet handled in Linux kernel

```
        b'tcp_v4_err+0x1'
        b'icmp_unreach+0x91'
        b'icmp_rcv+0x19f'
        b'ip_protocol_deliver_rcu+0x1da'
        b'ip_local_deliver_finish+0x48'
        b'ip_local_deliver+0xf3'
        b'ip_rcv+0x16b'
        b'__netif_receive_skb_one_core+0x86'
        b'__netif_receive_skb+0x15'
        b'process_backlog+0x9e'
        b'__napi_poll+0x33'
        b'net_rx_action+0x126'
        b'__do_softirq+0xd9'
        b'do_softirq+0x75'
        b'__local_bh_enable_ip+0x50'
        b'__icmp_send+0x55a'
        b'ip_fragment.constprop.0+0x7a'
        b'__ip_finish_output+0x13d'
        b'ip_finish_output+0x2e'
        b'ip_output+0x78'
        b'ip_local_out+0x5a'
        b'__ip_queue_xmit+0x180'
        b'ip_queue_xmit+0x15'
        b'__tcp_transmit_skb+0x8d9'
        b'tcp_write_xmit+0x3a7'
        b'__tcp_push_pending_frames+0x37'
        b'tcp_push+0xd2'
        b'tcp_sendmsg_locked+0x87f'
        b'tcp_sendmsg+0x2d'
        b'inet_sendmsg+0x43'
        b'sock_sendmsg+0x5e'
        b'sock_write_iter+0x93'
        b'do_iter_readv_writev+0x14d'
        b'do_iter_write+0x88'
        b'vfs_writev+0xaa'
        b'do_writev+0xe5'
        b'__x64_sys_writev+0x1c'
        b'do_syscall_64+0x5c'
        b'entry_SYSCALL_64_after_hwframe+0x44'

```

And if you trace for more, in the function tcp_v4_err(), the packet is handled by tcp_v4_mtu_reduced()  in tcp_v4_err().  This is still in the packet send context, which means that the socket is still held by the userspace, so tcp_v4_mtu_reduced() will not be called directly.

The tcp_v4_mtu_reduced() is called when it tries to release the socket by  release_sock(). In the tcp_v4_mtu_reduced(), it will call tcp_simple_retransmit() https://elixir.bootlin.com/linux/v5.15.126/source/net/ipv4/tcp_ipv4.c#L372 but the packet is not sent out, so tcp retransmission will not be triggered in this scenario unlock request A. 
https://elixir.bootlin.com/linux/v5.15.126/source/net/ipv4/tcp_input.c#L2770

And after trace for more, in this condition, the packet will be sent again during the handling of the tcp probe timer, which makes it take more than 200ms. 


```
        b'tcp_v4_send_check+0x1'
        b'tcp_write_wakeup+0x120'
        b'tcp_send_probe0+0x1d'
        b'tcp_probe_timer.constprop.0+0x17e'
        b'tcp_write_timer_handler+0x79'
        b'tcp_write_timer+0x9e'
        b'call_timer_fn+0x2b'
        b'__run_timers.part.0+0x1dd'
        b'run_timer_softirq+0x2a'
        b'__do_softirq+0xd9'
        b'irq_exit_rcu+0x8c'
        b'sysvec_apic_timer_interrupt+0x7c'
        b'asm_sysvec_apic_timer_interrupt+0x12'
        b'cpuidle_enter_state+0xd9'
        b'cpuidle_enter+0x2e'
        b'cpuidle_idle_call+0x13e'
        b'do_idle+0x83'
        b'cpu_startup_entry+0x20'
        b'start_secondary+0x12a'
        B'secondary_startup_64_no_verify+0xc2'

```



## Question 4:  If the route MTU cached changed in the fly, does it impact the connections that already established



From the tcpdump files of request A and request B, we can see that this impacts the new connections. But does it impact the connections that already established with MSS negotiated with MTU 1480?  

Unfortunately, the existing traffic will be impacted even if the MSS is negotiated with MTU 1480.

The mss is checked time to time during msg send in the tcp stack https://elixir.bootlin.com/linux/v5.15.126/source/net/ipv4/tcp_output.c#L1823

If the route MTU expires (route MTU will be cached for 600s by default), then MSS will be changed back from 1440 to 1460, and then the following request may also have this 200ms delay issue. 



