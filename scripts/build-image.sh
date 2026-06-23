#!/usr/bin/env bash
set -euo pipefail

IMAGE=${1:-dnsmon:dev}
docker build -t "$IMAGE" .
