package runner

import (
	"context"
	"math/rand"
	"time"

	"github.com/example/ebpf-dns-latency-monitor/internal/model"
)

func RunMock(ctx context.Context, c *Correlator) {
	domains := []string{"api.internal.svc.cluster.local", "payments.example.com", "does-not-exist.example.com", "metadata.google.internal"}
	client := MustAddr("10.244.1.42")
	server := MustAddr("10.96.0.10")
	t := time.NewTicker(350 * time.Millisecond)
	defer t.Stop()
	var txid uint16 = 100
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			txid++
			domain := domains[rand.Intn(len(domains))]
			q := model.DNSEvent{TimestampNS: uint64(now.UnixNano()), SrcIP: client, DstIP: server, SrcPort: 53123, DstPort: 53, TxID: txid, QType: 1, Kind: model.EventQuery, Direction: model.DirectionEgress, QName: domain}
			c.Process(ctx, q)
			if rand.Intn(10) == 0 {
				continue
			}
			latency := time.Duration(3+rand.Intn(350)) * time.Millisecond
			rcode := uint8(0)
			if domain == "does-not-exist.example.com" {
				rcode = model.RcodeNXDomain
			}
			r := model.DNSEvent{TimestampNS: uint64(now.Add(latency).UnixNano()), SrcIP: server, DstIP: client, SrcPort: 53, DstPort: 53123, TxID: txid, QType: 1, RCode: rcode, Kind: model.EventResponse, Direction: model.DirectionIngress, QName: domain}
			c.Process(ctx, r)
		}
	}
}
