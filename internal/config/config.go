package config

import (
	"flag"
	"strings"
	"time"
)

type Config struct {
	Mock              bool
	MetricsAddr       string
	IfaceNames        []string
	IfacePrefixes     []string
	Kubeconfig        string
	EnableKubernetes  bool
	LatencyThreshold  time.Duration
	TimeoutWindow     time.Duration
	DomainAllowSuffix []string
	DomainDenySuffix  []string
	AlertWebhookURL   string
	MaxDomainLabels   int
}

func Parse() Config {
	var ifaces string
	var prefixes string
	var allow string
	var deny string
	var latencyThreshold string
	var timeoutWindow string

	cfg := Config{}
	flag.BoolVar(&cfg.Mock, "mock", false, "run without eBPF and emit synthetic DNS events")
	flag.StringVar(&cfg.MetricsAddr, "metrics-addr", ":9090", "metrics listen address")
	flag.StringVar(&ifaces, "iface", "", "comma separated interface names to attach eBPF to")
	flag.StringVar(&prefixes, "iface-prefix", "veth,cali,cilium,flannel,eth", "comma separated interface prefixes to auto attach")
	flag.StringVar(&cfg.Kubeconfig, "kubeconfig", "", "optional kubeconfig path; in-cluster config is used when empty")
	flag.BoolVar(&cfg.EnableKubernetes, "kubernetes", true, "enable Kubernetes pod IP cache")
	flag.StringVar(&latencyThreshold, "latency-threshold", "200ms", "latency threshold for alerting")
	flag.StringVar(&timeoutWindow, "timeout-window", "2s", "DNS query timeout window")
	flag.StringVar(&allow, "domain-allow-suffix", "", "comma separated domain suffix allow-list")
	flag.StringVar(&deny, "domain-deny-suffix", "", "comma separated domain suffix deny-list")
	flag.StringVar(&cfg.AlertWebhookURL, "alert-webhook-url", "", "optional webhook URL for alert notifications")
	flag.IntVar(&cfg.MaxDomainLabels, "max-domain-labels", 5, "domain label cardinality guard; rightmost labels are retained")
	flag.Parse()

	cfg.IfaceNames = splitCSV(ifaces)
	cfg.IfacePrefixes = splitCSV(prefixes)
	cfg.DomainAllowSuffix = splitCSV(allow)
	cfg.DomainDenySuffix = splitCSV(deny)
	cfg.LatencyThreshold = mustDuration(latencyThreshold, 200*time.Millisecond)
	cfg.TimeoutWindow = mustDuration(timeoutWindow, 2*time.Second)
	return cfg
}

func splitCSV(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func mustDuration(v string, fallback time.Duration) time.Duration {
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
