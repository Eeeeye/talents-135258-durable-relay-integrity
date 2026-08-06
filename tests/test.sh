#!/bin/bash
set -Eeuo pipefail

install -d /logs/verifier
reward=0
finish() {
    printf '%s\n' "${reward}" > /logs/verifier/reward.txt
}
trap finish EXIT

export GOPROXY=off
export GOSUMDB=off
export GOTOOLCHAIN=local
export GOFLAGS=-mod=readonly
export CGO_ENABLED=0
export GOCACHE=/tmp/durable-relay-verifier-gocache
export GOPATH=/tmp/durable-relay-verifier-gopath

work_dir="$(mktemp -d /tmp/durable-relay-verifier.XXXXXX)"
bin_dir="${work_dir}/bin"
install -d "${bin_dir}"

cd /app
go test -buildvcs=false -count=1 ./... > /logs/verifier/unit-tests.log 2>&1
go build -trimpath -buildvcs=false -o "${bin_dir}/relayqd" ./cmd/relayqd
go build -trimpath -buildvcs=false -o "${bin_dir}/relayctl" ./cmd/relayctl
go build -trimpath -buildvcs=false -o "${bin_dir}/relayfixture" ./cmd/relayfixture
go build -trimpath -buildvcs=false -o "${bin_dir}/relayinspect" ./cmd/relayinspect
go build -trimpath -buildvcs=false -o "${work_dir}/verifier" /tests/support.go /tests/verifier.go

"${work_dir}/verifier" -bin-dir "${bin_dir}" > /logs/verifier/integration.log 2>&1
cat /logs/verifier/unit-tests.log
cat /logs/verifier/integration.log
reward=1
