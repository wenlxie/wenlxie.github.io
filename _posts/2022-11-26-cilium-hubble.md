---
layout: post
tags: eBPF cilium linux hubble
title: cilium hubble implementation
categories: eBPF
date: 2022-11-26 14:02:32-0700
excerpt: cilium hubble implementation
---


## Hubble event generate
  
### DataPlane
  
  Call the API: send_drop_notify_error(), send_trace*(), send_drop_notify(), cilium_dbg*() to send events perf_buff cilium_event.
  Cilium_event is a perf_buff, which is is 64 pages.
  Difference between perf buff vs ring buff : https://nakryiko.com/posts/bpf-ringbuf/

```
static __always_inline void
send_trace_notify(struct __ctx_buff *ctx, enum trace_point obs_point,
		  __u32 src, __u32 dst, __u16 dst_id, __u32 ifindex,
		  enum trace_reason reason, __u32 monitor)
{
	__u64 ctx_len = ctx_full_len(ctx);
	__u64 cap_len = min_t(__u64, monitor ? : TRACE_PAYLOAD_LEN,
			      ctx_len);
	struct trace_notify msg __align_stack_8;

	update_trace_metrics(ctx, obs_point, reason);

	if (!emit_trace_notify(obs_point, monitor))
		return;

	msg = (typeof(msg)) {
		__notify_common_hdr(CILIUM_NOTIFY_TRACE, obs_point),
		__notify_pktcap_hdr(ctx_len, (__u16)cap_len),
		.src_label	= src,
		.dst_label	= dst,
		.dst_id		= dst_id,
		.reason		= reason,
		.ifindex	= ifindex,
	};
	memset(&msg.orig_ip6, 0, sizeof(union v6addr));

	ctx_event_output(ctx, &EVENTS_MAP,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}
```

### ControlPlane
  
  Cilium agent calls api daemon.SendNotification when endpoint add/del and policy add/del.

```
// SendNotification sends an agent notification to the monitor
func (d *Daemon) SendNotification(notification monitorAPI.AgentNotifyMessage) error {
	if option.Config.DryMode {
		return nil
	}
	return d.monitorAgent.SendEvent(monitorAPI.MessageTypeAgent, notification)
}
```

## hubble agent
  
hubble agent register listener and consumer of the events, and the start a go routine to handle the events 
It only handles the events from data plane, 
Control plane events will be sent to listeners and consumers directly.

```
// startPerfReaderLocked starts the perf reader. This should only be
// called if there are no other readers already running.
// The goroutine is spawned with a context derived from m.Context() and the
// cancelFunc is assigned to perfReaderCancel. Note that cancelling m.Context()
// (e.g. on program shutdown) will also cancel the derived context.
// Note: it is critical to hold the lock for this operation.
func (a *Agent) startPerfReaderLocked() {
	if a.events == nil {
		return // not attached to events map yet
	}

	a.perfReaderCancel() // don't leak any old readers, just in case.
	perfEventReaderCtx, cancel := context.WithCancel(a.ctx)
	a.perfReaderCancel = cancel
	go a.handleEvents(perfEventReaderCtx)
}
```

It will get the events from perf buff cilium_events, and then start to handle the events. 

These events include lost events and normal events. Agent sent the events to the listeners and consumsers

In this step, events are still in raw data format. 


## hubble consumer
  
### hubble observer
  
This consumer only enabled when hubble enabled. 

```
func (d *Daemon) launchHubble() {
    ...
	d.hubbleObserver, err = observer.NewLocalServer(payloadParser, logger,
		observerOpts...,
	)
	if err != nil {
		logger.WithError(err).Error("Failed to initialize Hubble")
		return
	}
	go d.hubbleObserver.Start()
	d.monitorAgent.RegisterNewConsumer(monitor.NewConsumer(d.hubbleObserver))
    ...
}
```

### hubble recorder 
  
This consumer is enabled by config option.Config.EnableRecorder && option.Config.EnableHubbleRecorderAPI 

```
func (d *Daemon) launchHubble() {
    ...
	if option.Config.EnableRecorder && option.Config.EnableHubbleRecorderAPI {
		dispatch, err := sink.NewDispatch(option.Config.HubbleRecorderSinkQueueSize)
		if err != nil {
			logger.WithError(err).Error("Failed to initialize Hubble recorder sink dispatch")
			return
		}
		d.monitorAgent.RegisterNewConsumer(dispatch)
		svc, err := recorder.NewService(d.rec, dispatch,
			recorderoption.WithStoragePath(option.Config.HubbleRecorderStoragePath))
		if err != nil {
			logger.WithError(err).Error("Failed to initialize Hubble recorder service")
			return
		}
		localSrvOpts = append(localSrvOpts, serveroption.WithRecorderService(svc))
	}
    ...
}
```

## hubble listener 
  
```
	// We can only attach the monitor agent once cilium_event has been set up.
	if option.Config.RunMonitorAgent {
		err = d.monitorAgent.AttachToEventsMap(defaults.MonitorBufferPages)
		if err != nil {
			log.WithError(err).Error("encountered error configuring run monitor agent")
			return nil, nil, fmt.Errorf("encountered error configuring run monitor agent: %w", err)
		}

		if option.Config.EnableMonitor {
			err = monitoragent.ServeMonitorAPI(d.monitorAgent)
			if err != nil {
				log.WithError(err).Error("encountered error configuring run monitor agent")
				return nil, nil, fmt.Errorf("encountered error configuring run monitor agent: %w", err)
			}
		}
	}
```

```
// ServeMonitorAPI serves the Cilium 1.2 monitor API on a unix domain socket.
// This method starts the server in the background. The server is stopped when
// monitor.Context() is cancelled. Each incoming connection registers a new
// listener on monitor.
func ServeMonitorAPI(monitor *Agent) error {
	listener, err := buildServer(defaults.MonitorSockPath1_2)
	if err != nil {
		return err
	}

	s := &server{
		listener: listener,
		monitor:  monitor,
	}

	log.Infof("Serving cilium node monitor v1.2 API at unix://%s", defaults.MonitorSockPath1_2)

	go s.connectionHandler1_2(monitor.Context())

	return nil
}

// connectionHandler1_2 handles all the incoming connections and sets up the
// listener objects. It will block until ctx is cancelled.
func (s *server) connectionHandler1_2(ctx context.Context) {
	go func() {
		<-ctx.Done()
		s.listener.Close()
	}()

	for !isCtxDone(ctx) {
		conn, err := s.listener.Accept()
		switch {
		case isCtxDone(ctx):
			if conn != nil {
				conn.Close()
			}
			return
		case err != nil:
			log.WithError(err).Warn("Error accepting connection")
			continue
		}

		newListener := newListenerv1_2(conn, option.Config.MonitorQueueSize, s.monitor.RemoveListener)
		s.monitor.RegisterNewListener(newListener)
	}
}

```

## events handling by consumer
  
### hubble observer 
  
- start a go routine the handle the events

    ```
    go d.hubbleObserver.Start()
    ```

- Get the events from channel , events are sent from hubble agent
- Call OnMonitorEvent to run the hook before decode the events. For this consumer, actually there is nothing to handle here. 

    ```
          for _, f := range s.opts.OnMonitorEvent {
              stop, err := f.OnMonitorEvent(ctx, monitorEvent)
              if err != nil {
                  s.log.WithError(err).WithField("event", monitorEvent).Info("failed in OnMonitorEvent")
              }
              if stop {
                  continue nextEvent
              }
          }
    ```
  
- Decode the events

    -  perf event
    
    -  dbg events 
      
      Add endpoint info by ip 
      
    -  l34 events
       
      Add L3, L4 metadata to the events. Medata includes but not limited: Endpoint info, pod info, 5 tuples ... 
    
    -  agent event
    
      - Handle the message from L7, then decode the L7 event and add metadata
      
      - Handle the message from the monitor agent
      
    -  lost event
    
    -  decode flows to add metrics.
  
      ```

          if flow, ok := ev.Event.(*flowpb.Flow); ok {
              for _, f := range s.opts.OnDecodedFlow {
                  stop, err := f.OnDecodedFlow(ctx, flow)
                  if err != nil {
                      s.log.WithError(err).WithField("event", monitorEvent).Info("failed in OnDecodedFlow")
                  }
                  if stop {
                      continue nextEvent
                  }
              }

              atomic.AddUint64(&s.numObservedFlows, 1)
          }

      ```


-  Call onDecodeEvent()  to execute the hook after event decoded

      ```
          for _, f := range s.opts.OnDecodedEvent {
              stop, err := f.OnDecodedEvent(ctx, ev)
              if err != nil {
                  s.log.WithError(err).WithField("event", ev).Info("failed in OnDecodedEvent")
              }
              if stop {
                  continue nextEvent
              }
          }
      ```

### hubble recorder
  
-  Get the request from the client, and the start to record
  
      ```
            startRecording := req.GetStart()
            if startRecording == nil {
                return fmt.Errorf("received invalid request %q, expected start request", req)
            }

            // The startRecording helper spawns a clean up go routine to remove all
            // state associated with this recording when the context ctx is cancelled.
            recording, filePath, err = s.startRecording(ctx, startRecording)
            if err != nil {
                return err
            }
      ```

-  Create the pcap file, get the events from queue and then send response

        ```
        func (s *Service) startRecording(
        ctx context.Context,
        req *recorderpb.StartRecording,
        ) (handle *sink.Handle, filePath string, err error) {
        ---
        filters, err := parseFilters(req.GetInclude())
        if err != nil {
            return nil, "", err
        }
        ---
        var f *os.File
        f, filePath, err = createPcapFile(s.opts.StoragePath, prefix)
        if err != nil {
            return nil, "", err
        }
        ---
        handle, err = s.dispatch.StartSink(ctx, config)
        if err != nil {
            return nil, "", err
        }
        ---
        }
	
        ```
    
        ``` 
        func startSink(ctx context.Context, p PcapSink, queueSize int) *sink {
        ---
        for {
        select {
        // s.queue will be closed when the sink is unregistered
        case rec := <-s.queue:
        pcapRecord := pcap.Record{
        Timestamp:      rec.timestamp,
        CaptureLength:  rec.inclLen,
        OriginalLength: rec.origLen,
        }

        if err = p.Writer.WriteRecord(pcapRecord, rec.data); err != nil {
                        return
                    }

                    stats := s.addToStatistics(Statistics{
                        PacketsWritten: 1,
                        BytesWritten:   uint64(rec.inclLen),
                    })
                    if (stop.PacketsCaptured > 0 && stats.PacketsWritten >= stop.PacketsCaptured) ||
                        (stop.BytesCaptured > 0 && stats.BytesWritten >= stop.BytesCaptured) {
                        return
                    }
                case <-s.shutdown:
                    return
                case <-stopAfter:
                    // duration of stop condition has been reached
                    return
                case <-ctx.Done():
                    err = ctx.Err()
                    return
                }
            }
        ---
        }
        ```

## events handling by listener
  
- ServeMonitorAPI() accept the monitor request, and create a listener for the request

```
// ServeMonitorAPI serves the Cilium 1.2 monitor API on a unix domain socket.
// This method starts the server in the background. The server is stopped when
// monitor.Context() is cancelled. Each incoming connection registers a new
// listener on monitor.
func ServeMonitorAPI(monitor *Agent) error {
	listener, err := buildServer(defaults.MonitorSockPath1_2)
	if err != nil {
		return err
	}

	s := &server{
		listener: listener,
		monitor:  monitor,
	}

	log.Infof("Serving cilium node monitor v1.2 API at unix://%s", defaults.MonitorSockPath1_2)

	go s.connectionHandler1_2(monitor.Context())

	return nil
}

// connectionHandler1_2 handles all the incoming connections and sets up the
// listener objects. It will block until ctx is cancelled.
func (s *server) connectionHandler1_2(ctx context.Context) {
	go func() {
		<-ctx.Done()
		s.listener.Close()
	}()

	for !isCtxDone(ctx) {
		conn, err := s.listener.Accept()
		switch {
		case isCtxDone(ctx):
			if conn != nil {
				conn.Close()
			}
			return
		case err != nil:
			log.WithError(err).Warn("Error accepting connection")
			continue
		}

		newListener := newListenerv1_2(conn, option.Config.MonitorQueueSize, s.monitor.RemoveListener)
		s.monitor.RegisterNewListener(newListener)
	}
}

```

- drain the queue

```
func newListenerv1_2(c net.Conn, queueSize int, cleanupFn func(listener.MonitorListener)) *listenerv1_2 {
	ml := &listenerv1_2{
		conn:      c,
		queue:     make(chan *payload.Payload, queueSize),
		cleanupFn: cleanupFn,
	}

	go ml.drainQueue()

	return ml
}
```

In drainQuque(), the events with be encoded, and then remove the listener. 

```
// drainQueue encodes and sends monitor payloads to the listener. It is
// intended to be a goroutine.
func (ml *listenerv1_2) drainQueue() {
	defer func() {
		ml.cleanupFn(ml)
	}()

	enc := gob.NewEncoder(ml.conn)
	for pl := range ml.queue {
		if err := pl.EncodeBinary(enc); err != nil {
			switch {
			case listener.IsDisconnected(err):
				log.Debug("Listener disconnected")
				return

			default:
				log.WithError(err).Warn("Removing listener due to write failure")
				return
			}
		}
	}
}
```

## hubble observer vs cilium monitor
  
hubble observer has the metadata like endpoint related infos. 

## client
  
- hubble observe client sends the requests to hubble observer grpc server in the cilium agent. Filter will be applied in grpc server side

- cilium monitor get the events fro the agent listener, then it will add the filed name to the events in client side. 

## Hubble functions
  
![](/assets/2022-11-26-cilium-hubble.png)
