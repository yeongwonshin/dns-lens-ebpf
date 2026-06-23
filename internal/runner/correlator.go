package runner

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/example/ebpf-dns-latency-monitor/internal/alerts"
	"github.com/example/ebpf-dns-latency-monitor/internal/dns"
	"github.com/example/ebpf-dns-latency-monitor/internal/metrics"
	"github.com/example/ebpf-dns-latency-monitor/internal/model"
	"github.com/example/ebpf-dns-latency-monitor/internal/podcache"
)

type Correlator struct {
	mu        sync.Mutex
	queries   map[queryKey]queryState
	timeout   time.Duration
	threshold time.Duration
	podCache  *podcache.Cache
	metrics   *metrics.Recorder
	notifier  alerts.Notifier
	allow     []string
	deny      []string
	maxLabels int
}

type queryKey struct {
	client string
	server string
	txid   uint16
	qtype  uint16
	qname  string
}

type queryState struct {
	seenAt time.Time
	event  model.DNSEvent
}

func NewCorrelator(timeout, threshold time.Duration, pc *podcache.Cache, rec *metrics.Recorder, notifier alerts.Notifier, allow, deny []string, maxLabels int) *Correlator {
	return &Correlator{
		queries:   map[queryKey]queryState{},
		timeout:   timeout,
		threshold: threshold,
		podCache:  pc,
		metrics:   rec,
		notifier:  notifier,
		allow:     allow,
		deny:      deny,
		maxLabels: maxLabels,
	}
}

func (c *Correlator) RunTimeoutScanner(ctx context.Context) {
	t := time.NewTicker(c.timeout / 2)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			c.scanTimeouts(ctx, now)
		}
	}
}

func (c *Correlator) Process(ctx context.Context, ev model.DNSEvent) {
	domain := dns.NormalizeDomain(ev.QName, c.maxLabels)
	if domain == "" || !dns.AllowedDomain(domain, c.allow, c.deny) {
		return
	}
	ev.QName = domain
	if ev.Kind == model.EventQuery {
		c.remember(ev)
		return
	}
	if ev.Kind == model.EventResponse {
		c.observeResponse(ctx, ev)
	}
}

func (c *Correlator) remember(ev model.DNSEvent) {
	key := keyFromQuery(ev)
	c.mu.Lock()
	c.queries[key] = queryState{seenAt: time.Unix(0, int64(ev.TimestampNS)), event: ev}
	c.metrics.Inflight.Set(float64(len(c.queries)))
	c.mu.Unlock()
}

func (c *Correlator) observeResponse(ctx context.Context, ev model.DNSEvent) {
	key := keyFromResponse(ev)
	c.mu.Lock()
	qs, ok := c.queries[key]
	if ok {
		delete(c.queries, key)
	}
	c.metrics.Inflight.Set(float64(len(c.queries)))
	c.mu.Unlock()
	if !ok {
		slog.Debug("unmatched dns response", "domain", ev.QName, "txid", ev.TxID)
		return
	}
	latency := time.Unix(0, int64(ev.TimestampNS)).Sub(qs.seenAt)
	if latency < 0 {
		latency = 0
	}
	pod := c.podCache.Lookup(key.client)
	ns, podName := pod.Labels()
	server := key.server
	rcode := rcodeString(ev.RCode)
	c.metrics.ObserveResponse(ns, podName, ev.QName, server, rcode, latency)
	if latency >= c.threshold {
		c.metrics.ObserveAlert("latency", ns, podName, ev.QName, server)
		c.notifier.Notify(ctx, alerts.Event{
			Type:      "latency",
			Namespace: ns,
			Pod:       podName,
			Domain:    ev.QName,
			Server:    server,
			Latency:   latency,
			Threshold: c.threshold,
			Message:   fmt.Sprintf("DNS latency %s exceeded threshold %s", latency, c.threshold),
		})
	}
}

func (c *Correlator) scanTimeouts(ctx context.Context, now time.Time) {
	var expired []queryState
	c.mu.Lock()
	for key, qs := range c.queries {
		if now.Sub(qs.seenAt) >= c.timeout {
			expired = append(expired, qs)
			delete(c.queries, key)
		}
	}
	c.metrics.Inflight.Set(float64(len(c.queries)))
	c.mu.Unlock()

	for _, qs := range expired {
		client := qs.event.SrcIP.String()
		server := qs.event.DstIP.String()
		pod := c.podCache.Lookup(client)
		ns, podName := pod.Labels()
		c.metrics.ObserveTimeout(ns, podName, qs.event.QName, server)
		c.metrics.ObserveAlert("timeout", ns, podName, qs.event.QName, server)
		c.notifier.Notify(ctx, alerts.Event{
			Type:      "timeout",
			Namespace: ns,
			Pod:       podName,
			Domain:    qs.event.QName,
			Server:    server,
			Latency:   now.Sub(qs.seenAt),
			Threshold: c.timeout,
			Message:   "DNS response was not observed within timeout window",
		})
	}
}

func keyFromQuery(ev model.DNSEvent) queryKey {
	return queryKey{client: ev.SrcIP.String(), server: ev.DstIP.String(), txid: ev.TxID, qtype: ev.QType, qname: ev.QName}
}

func keyFromResponse(ev model.DNSEvent) queryKey {
	return queryKey{client: ev.DstIP.String(), server: ev.SrcIP.String(), txid: ev.TxID, qtype: ev.QType, qname: ev.QName}
}

func rcodeString(v uint8) string {
	switch v {
	case 0:
		return "NOERROR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE_%d", v)
	}
}

func MustAddr(s string) netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return addr
}
