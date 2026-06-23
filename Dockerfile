FROM golang:1.23-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm make gcc linux-libc-dev libbpf-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN make generate && make build

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /src/bin/dnsmon /dnsmon
USER 65532:65532
ENTRYPOINT ["/dnsmon"]
