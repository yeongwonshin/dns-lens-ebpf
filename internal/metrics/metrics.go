package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Recorder struct {
	QueriesTotal *prometheus.CounterVec
	Latency      *prometheus.HistogramVec
	Timeouts     *prometheus.CounterVec
	NXDomain     *prometheus.CounterVec
	ServFail     *prometheus.CounterVec
	Inflight     prometheus.Gauge
	Alerts       *prometheus.CounterVec
}

func New(reg prometheus.Registerer) *Recorder {
	factory := promauto.With(reg)
	return &Recorder{
		QueriesTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "dnsmon_queries_total",
			Help: "Total DNS responses observed by dnsmon.",
		}, []string{"namespace", "pod", "domain", "server", "rcode"}),
		Latency: factory.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "dnsmon_latency_seconds",
			Help:    "DNS query to response latency by pod, domain and server.",
			Buckets: []float64{0.001, 0.003, 0.005, 0.010, 0.025, 0.050, 0.100, 0.200, 0.500, 1.0, 2.0, 5.0},
		}, []string{"namespace", "pod", "domain", "server"}),
		Timeouts: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "dnsmon_timeouts_total",
			Help: "DNS queries that did not receive a response within timeout window.",
		}, []string{"namespace", "pod", "domain", "server"}),
		NXDomain: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "dnsmon_nxdomain_total",
			Help: "DNS NXDOMAIN responses observed by dnsmon.",
		}, []string{"namespace", "pod", "domain", "server"}),
		ServFail: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "dnsmon_servfail_total",
			Help: "DNS SERVFAIL responses observed by dnsmon.",
		}, []string{"namespace", "pod", "domain", "server"}),
		Inflight: factory.NewGauge(prometheus.GaugeOpts{
			Name: "dnsmon_inflight_queries",
			Help: "DNS queries currently waiting for a response.",
		}),
		Alerts: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "dnsmon_alerts_total",
			Help: "DNS latency/timeout alerts emitted by dnsmon.",
		}, []string{"type", "namespace", "pod", "domain", "server"}),
	}
}

func (r *Recorder) ObserveResponse(ns, pod, domain, server, rcode string, latency time.Duration) {
	r.QueriesTotal.WithLabelValues(ns, pod, domain, server, rcode).Inc()
	r.Latency.WithLabelValues(ns, pod, domain, server).Observe(latency.Seconds())
	if rcode == "NXDOMAIN" {
		r.NXDomain.WithLabelValues(ns, pod, domain, server).Inc()
	}
	if rcode == "SERVFAIL" {
		r.ServFail.WithLabelValues(ns, pod, domain, server).Inc()
	}
}

func (r *Recorder) ObserveTimeout(ns, pod, domain, server string) {
	r.Timeouts.WithLabelValues(ns, pod, domain, server).Inc()
}

func (r *Recorder) ObserveAlert(kind, ns, pod, domain, server string) {
	r.Alerts.WithLabelValues(kind, ns, pod, domain, server).Inc()
}

func Handler(reg *prometheus.Registry) http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}
