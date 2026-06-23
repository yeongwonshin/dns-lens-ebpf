package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -type dns_event Dnsmon ../../bpf/dnsmon.bpf.c -- -I../../bpf -O2 -g

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/example/ebpf-dns-latency-monitor/internal/alerts"
	"github.com/example/ebpf-dns-latency-monitor/internal/config"
	"github.com/example/ebpf-dns-latency-monitor/internal/metrics"
	"github.com/example/ebpf-dns-latency-monitor/internal/model"
	"github.com/example/ebpf-dns-latency-monitor/internal/podcache"
	"github.com/example/ebpf-dns-latency-monitor/internal/runner"
	"github.com/prometheus/client_golang/prometheus"
)

type rawDNSEvent struct {
	TimestampNS uint64
	SrcIP       [4]byte
	DstIP       [4]byte
	SrcPort     uint16
	DstPort     uint16
	TxID        uint16
	QType       uint16
	RCode       uint8
	Direction   uint8
	Kind        uint8
	QNameLen    uint8
	QName       [128]byte
}

type attachedLink struct {
	iface string
	dir   string
	link  link.Link
}

func main() {
	cfg := config.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	reg := prometheus.NewRegistry()
	rec := metrics.New(reg)
	pc := podcache.New()

	notifier := alerts.NewMulti(alerts.LogNotifier{}, alerts.WebhookNotifier{URL: cfg.AlertWebhookURL})
	corr := runner.NewCorrelator(cfg.TimeoutWindow, cfg.LatencyThreshold, pc, rec, notifier, cfg.DomainAllowSuffix, cfg.DomainDenySuffix, cfg.MaxDomainLabels)
	go corr.RunTimeoutScanner(ctx)

	if cfg.EnableKubernetes {
		go func() {
			if err := pc.Run(ctx, cfg.Kubeconfig); err != nil && !errors.Is(err, context.Canceled) {
				slog.Warn("kubernetes pod cache stopped", "error", err)
			}
		}()
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", metrics.Handler(reg))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	server := &http.Server{Addr: cfg.MetricsAddr, Handler: mux, ReadHeaderTimeout: 2 * time.Second}
	go func() {
		slog.Info("metrics server listening", "addr", cfg.MetricsAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("metrics server stopped", "error", err)
			stop()
		}
	}()

	if cfg.Mock {
		slog.Info("starting mock event generator")
		runner.RunMock(ctx, corr)
		return
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		slog.Warn("remove memlock limit", "error", err)
	}

	var objs dnsmonObjects
	if err := loadDnsmonObjects(&objs, nil); err != nil {
		slog.Error("load eBPF objects", "error", err)
		os.Exit(1)
	}
	defer objs.Close()

	links, err := attachPrograms(cfg, &objs)
	if err != nil {
		slog.Error("attach eBPF programs", "error", err)
		os.Exit(1)
	}
	defer func() {
		for _, l := range links {
			_ = l.link.Close()
		}
	}()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		slog.Error("open ringbuf", "error", err)
		os.Exit(1)
	}
	defer rd.Close()

	go func() {
		<-ctx.Done()
		_ = rd.Close()
		_ = server.Shutdown(context.Background())
	}()

	slog.Info("dnsmon started", "attached_links", len(links))
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return
			}
			slog.Warn("read ringbuf", "error", err)
			continue
		}
		ev, err := decodeEvent(record.RawSample)
		if err != nil {
			slog.Debug("decode dns event", "error", err)
			continue
		}
		corr.Process(ctx, ev)
	}
}

func attachPrograms(cfg config.Config, objs *dnsmonObjects) ([]attachedLink, error) {
	ifaces, err := selectInterfaces(cfg)
	if err != nil {
		return nil, err
	}
	if len(ifaces) == 0 {
		return nil, fmt.Errorf("no network interface matched; use --iface or --iface-prefix")
	}
	links := make([]attachedLink, 0, len(ifaces)*2)
	for _, iface := range ifaces {
		ingress, err := attachTCX(iface, objs.DnsIngress, ebpf.AttachTCXIngress)
		if err != nil {
			slog.Warn("attach ingress failed", "iface", iface.Name, "error", err)
		} else {
			links = append(links, attachedLink{iface: iface.Name, dir: "ingress", link: ingress})
		}
		egress, err := attachTCX(iface, objs.DnsEgress, ebpf.AttachTCXEgress)
		if err != nil {
			slog.Warn("attach egress failed", "iface", iface.Name, "error", err)
		} else {
			links = append(links, attachedLink{iface: iface.Name, dir: "egress", link: egress})
		}
	}
	if len(links) == 0 {
		return nil, fmt.Errorf("all tcx attaches failed; check kernel support or add classic tc fallback")
	}
	return links, nil
}

func attachTCX(iface net.Interface, prog *ebpf.Program, attach ebpf.AttachType) (link.Link, error) {
	return link.AttachTCX(link.TCXOptions{Interface: iface.Index, Program: prog, Attach: attach})
}

func selectInterfaces(cfg config.Config) ([]net.Interface, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	wanted := map[string]bool{}
	for _, name := range cfg.IfaceNames {
		wanted[name] = true
	}
	var out []net.Interface
	for _, iface := range all {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		if len(wanted) > 0 {
			if wanted[iface.Name] {
				out = append(out, iface)
			}
			continue
		}
		for _, prefix := range cfg.IfacePrefixes {
			if strings.HasPrefix(iface.Name, prefix) {
				out = append(out, iface)
				break
			}
		}
	}
	return out, nil
}

func decodeEvent(raw []byte) (model.DNSEvent, error) {
	var e rawDNSEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
		return model.DNSEvent{}, err
	}
	qlen := int(e.QNameLen)
	if qlen <= 0 || qlen > len(e.QName) {
		qlen = bytes.IndexByte(e.QName[:], 0)
		if qlen < 0 {
			qlen = len(e.QName)
		}
	}
	return model.DNSEvent{
		TimestampNS: e.TimestampNS,
		SrcIP:       netip.AddrFrom4(e.SrcIP),
		DstIP:       netip.AddrFrom4(e.DstIP),
		SrcPort:     e.SrcPort,
		DstPort:     e.DstPort,
		TxID:        e.TxID,
		QType:       e.QType,
		RCode:       e.RCode,
		Direction:   e.Direction,
		Kind:        e.Kind,
		QName:       string(e.QName[:qlen]),
	}, nil
}
