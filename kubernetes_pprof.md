# pprof for runtime profiling data
- Kubernetes is developed using go language. So how to get the stacks when go routine hangs? Tools like GDB?
- Kubernetes integrates package  “net/http/pprof”
- Package pprof serves via its HTTP server runtime profiling data in the format expected by the pprof visualization tool.
- pprof package link: https://golang.org/pkg/net/http/pprof/

# kubernets pprof
- ## kubelet
  link: `localhost:10248/debug/pprof/goroutine?debug=2`
- ## kube-controller-manager
  link: `localhost:10252/debug/pprof/goroutine?debug=2`
- ## kube-scheduler
  link: `localhost:10251/debug/pprof/goroutine?debug=2`
- ## kube-proxy
  link: `localhost:10249/debug/pprof/goroutine?debug=2` 

