#!/bin/bash
set -Eeuo pipefail

cp -a /solution/files/. /app/

cd /app
gofmt -w \
    internal/config/config.go \
    internal/config/manager.go \
    internal/engine/compact.go \
    internal/engine/engine.go \
    internal/engine/view.go \
    internal/engine/worker.go \
    internal/ledger/ledger.go \
    internal/publisher/publisher.go \
    internal/server/server.go \
    internal/snapshot/store.go \
    internal/wal/append.go \
    internal/wal/recover.go \
    internal/wal/writer.go

go test -buildvcs=false ./...
make build
