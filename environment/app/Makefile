.PHONY: all build test clean reproduce

GO ?= go
BIN_DIR ?= bin
GO_BUILD_FLAGS ?= -trimpath -buildvcs=false

all: build

build:
	mkdir -p $(BIN_DIR)
	$(GO) build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/relayqd ./cmd/relayqd
	$(GO) build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/relayctl ./cmd/relayctl
	$(GO) build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/relayfixture ./cmd/relayfixture
	$(GO) build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/relayinspect ./cmd/relayinspect

test:
	$(GO) test -buildvcs=false ./...

reproduce: build
	./scripts/reproduce-incident.sh

clean:
	rm -rf -- $(BIN_DIR) .incident-work
