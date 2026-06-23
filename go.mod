module github.com/example/ebpf-dns-latency-monitor

go 1.23

require (
	github.com/cilium/ebpf v0.18.0
	github.com/prometheus/client_golang v1.23.0
	k8s.io/api v0.34.0
	k8s.io/apimachinery v0.34.0
	k8s.io/client-go v0.34.0
)
