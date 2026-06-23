APP := dnsmon
PKG := ./cmd/dnsmon
BIN_DIR := bin

.PHONY: all generate build test fmt lint clean docker

all: generate build

generate:
	go generate ./cmd/dnsmon

build:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o $(BIN_DIR)/$(APP) $(PKG)

test: generate
	go test ./...

fmt:
	gofmt -w cmd internal

lint:
	go vet ./...

clean:
	rm -rf $(BIN_DIR)
	rm -f cmd/dnsmon/dnsmon_bpf*.go cmd/dnsmon/dnsmon_bpf*.o

docker:
	docker build -t dnsmon:dev .
