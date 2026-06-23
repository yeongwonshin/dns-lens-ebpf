package model

import "net/netip"

const (
	DirectionEgress  uint8 = 1
	DirectionIngress uint8 = 2

	EventQuery    uint8 = 1
	EventResponse uint8 = 2

	RcodeNoError  uint8 = 0
	RcodeNXDomain uint8 = 3
	RcodeServFail uint8 = 2
)

type DNSEvent struct {
	TimestampNS uint64
	SrcIP       netip.Addr
	DstIP       netip.Addr
	SrcPort     uint16
	DstPort     uint16
	TxID        uint16
	QType       uint16
	RCode       uint8
	Direction   uint8
	Kind        uint8
	QName       string
}

type PodRef struct {
	Namespace string
	Name      string
	NodeName  string
	IP        string
}

func (p PodRef) Labels() (namespace string, pod string) {
	if p.Namespace == "" {
		return "unknown", "unknown"
	}
	return p.Namespace, p.Name
}
