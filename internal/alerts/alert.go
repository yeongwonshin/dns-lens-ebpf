package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

type Event struct {
	Type      string        `json:"type"`
	Namespace string        `json:"namespace"`
	Pod       string        `json:"pod"`
	Domain    string        `json:"domain"`
	Server    string        `json:"server"`
	Latency   time.Duration `json:"latency"`
	Threshold time.Duration `json:"threshold"`
	Message   string        `json:"message"`
}

type Notifier interface {
	Notify(ctx context.Context, e Event)
}

type Multi struct {
	notifiers []Notifier
}

func NewMulti(items ...Notifier) *Multi {
	return &Multi{notifiers: items}
}

func (m *Multi) Notify(ctx context.Context, e Event) {
	for _, n := range m.notifiers {
		if n != nil {
			n.Notify(ctx, e)
		}
	}
}

type LogNotifier struct{}

func (LogNotifier) Notify(_ context.Context, e Event) {
	slog.Warn("dns alert", "type", e.Type, "namespace", e.Namespace, "pod", e.Pod, "domain", e.Domain, "server", e.Server, "latency", e.Latency.String(), "threshold", e.Threshold.String(), "message", e.Message)
}

type WebhookNotifier struct {
	URL    string
	Client *http.Client
}

func (w WebhookNotifier) Notify(ctx context.Context, e Event) {
	if w.URL == "" {
		return
	}
	client := w.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second}
	}
	body, _ := json.Marshal(e)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		slog.Warn("build alert webhook request", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		slog.Warn("send alert webhook", "error", err)
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 {
		slog.Warn("alert webhook returned non-2xx", "status", resp.StatusCode)
	}
}
