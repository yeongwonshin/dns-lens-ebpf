#!/usr/bin/env bash
set -euo pipefail

go run ./cmd/dnsmon \
  --mock \
  --metrics-addr=:9090 \
  --latency-threshold=120ms \
  --timeout-window=2s
