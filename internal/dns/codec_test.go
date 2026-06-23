package dns

import "testing"

func TestParseQuestion(t *testing.T) {
	payload := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	m, err := ParseQuestion(payload)
	if err != nil {
		t.Fatalf("ParseQuestion() error = %v", err)
	}
	if m.TxID != 0x1234 || m.QName != "www.example.com" || m.QType != 1 || m.IsReply {
		t.Fatalf("unexpected message: %+v", m)
	}
}

func TestNormalizeDomain(t *testing.T) {
	got := NormalizeDomain("A.B.C.D.EXAMPLE.COM.", 3)
	if got != "d.example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestAllowedDomain(t *testing.T) {
	if !AllowedDomain("api.example.com", []string{"example.com"}, nil) {
		t.Fatal("expected allowed")
	}
	if AllowedDomain("api.bad.com", []string{"example.com"}, nil) {
		t.Fatal("expected denied by allow list")
	}
	if AllowedDomain("api.example.com", nil, []string{"example.com"}) {
		t.Fatal("expected denied by deny list")
	}
}
