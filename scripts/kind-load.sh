#!/usr/bin/env bash
set -euo pipefail

IMAGE=${1:-dnsmon:dev}
CLUSTER=${2:-kind}
kind load docker-image "$IMAGE" --name "$CLUSTER"
