- [ ] The difference stack traced by ftrace function and kprobe stack trace.
      When I trace tcp_drop function by ftrace function tracer and kprobe stacktrace.  It shows differenet result.
 
- ftrace
```
<idle>-0     [034] ..s. 66307.162513: tcp_drop <-tcp_validate_incoming
 ```

tcp_drop is called by tcp_validate_incoming()

- stacktrace

 ```
 => kprobe_ftrace_handler
 => ftrace_ops_list_func
 => ftrace_regs_call
 => tcp_drop
 => tcp_rcv_established
 => tcp_v4_do_rcv
 => tcp_v4_rcv
 => ip_protocol_deliver_rcu
 => ip_local_deliver_finish
 => ip_local_deliver
 => ip_rcv_finish
 => ip_rcv
 => __netif_receive_skb_one_core
 => __netif_receive_skb
 => process_backlog
 => net_rx_action
 => __do_softirq
 ```

tcp_drop() is called in tcp_rcv_established().

We can see the same stack info by bcc tool [tcpdrop](https://github.com/iovisor/bcc/blob/master/tools/tcpdrop.py)

Function call: 

tcp_rcv_established() ---> tcp_drop() 

tcp_rcv_established() ---> tcp_validate_incoming() ---> tcp_drop()

If we just check the stack, then it is a big misleading because tcp_drop() is called by tcp_validate_incoming()  but not called by tcp_rcv_established() directly. 

gcc has a parameter to optimise static function to be inline, but tcp_validate_incoming() is called twice. 


tcp_rcv_established() ---> tcp_validate_incoming()  

tcp_rcv_state_process() --->  tcp_validate_incoming() 


```
-finline-functions-called-once
 Consider all "static" functions called once for inlining into their caller even if they are not marked "inline".  If a call to a given function is integrated, then the function is not output as assembler code in its own right.
 Enabled at levels -O1, -O2, -O3 and -Os.
```



