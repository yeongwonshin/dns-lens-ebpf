package dns

import (
	"encoding/binary"
	"errors"
	"strings"
)

var ErrInvalidDNS = errors.New("invalid dns packet")

type Message struct {
	TxID     uint16
	IsReply  bool
	RCode    uint8
	QType    uint16
	QName    string
	Question bool
}

func ParseQuestion(payload []byte) (Message, error) {
	if len(payload) < 12 {
		return Message{}, ErrInvalidDNS
	}
	m := Message{
		TxID:    binary.BigEndian.Uint16(payload[0:2]),
		IsReply: payload[2]&0x80 != 0,
		RCode:   payload[3] & 0x0f,
	}
	qd := binary.BigEndian.Uint16(payload[4:6])
	if qd == 0 {
		return m, nil
	}
	name, off, err := parseName(payload, 12, 0)
	if err != nil {
		return Message{}, err
	}
	if off+4 > len(payload) {
		return Message{}, ErrInvalidDNS
	}
	m.QType = binary.BigEndian.Uint16(payload[off : off+2])
	m.QName = name
	m.Question = true
	return m, nil
}

func NormalizeDomain(domain string, maxLabels int) string {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" || maxLabels <= 0 {
		return domain
	}
	labels := strings.Split(domain, ".")
	if len(labels) <= maxLabels {
		return domain
	}
	return strings.Join(labels[len(labels)-maxLabels:], ".")
}

func AllowedDomain(domain string, allowSuffixes, denySuffixes []string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, deny := range denySuffixes {
		deny = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(deny), "."))
		if deny != "" && (domain == deny || strings.HasSuffix(domain, "."+deny)) {
			return false
		}
	}
	if len(allowSuffixes) == 0 {
		return true
	}
	for _, allow := range allowSuffixes {
		allow = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(allow), "."))
		if allow != "" && (domain == allow || strings.HasSuffix(domain, "."+allow)) {
			return true
		}
	}
	return false
}

func parseName(packet []byte, off int, depth int) (string, int, error) {
	if depth > 8 || off >= len(packet) {
		return "", off, ErrInvalidDNS
	}
	labels := make([]string, 0, 8)
	pos := off
	for {
		if pos >= len(packet) {
			return "", pos, ErrInvalidDNS
		}
		ln := int(packet[pos])
		pos++
		if ln == 0 {
			break
		}
		if ln&0xc0 == 0xc0 {
			if pos >= len(packet) {
				return "", pos, ErrInvalidDNS
			}
			ptr := ((ln & 0x3f) << 8) | int(packet[pos])
			name, _, err := parseName(packet, ptr, depth+1)
			if err != nil {
				return "", pos, err
			}
			labels = append(labels, strings.Split(name, ".")...)
			pos++
			break
		}
		if ln > 63 || pos+ln > len(packet) {
			return "", pos, ErrInvalidDNS
		}
		labels = append(labels, string(packet[pos:pos+ln]))
		pos += ln
	}
	return strings.Join(labels, "."), pos, nil
}
