#!/bin/bash
set -Eeuo pipefail

umask 077
install -d -m 0700 /logs/verifier
reward=0
finish() {
    /usr/bin/pkill -KILL -u 65534 >/dev/null 2>&1 || true
    printf '%s\n' "${reward}" > /logs/verifier/reward.txt
}
trap finish EXIT

export GOPROXY=off
export GOSUMDB=off
export GOTOOLCHAIN=local
export GOFLAGS=-mod=readonly
export CGO_ENABLED=0

work_dir="$(mktemp -d /tmp/durable-relay-verifier.XXXXXX)"
bin_dir="${work_dir}/bin"
root_cache="${work_dir}/root-gocache"
install -d -m 0700 "${bin_dir}" "${root_cache}"
export GOCACHE="${root_cache}"
export GOPATH="${work_dir}/root-gopath"

cd /app
/usr/local/go/bin/go build -trimpath -buildvcs=false -o "${work_dir}/verifier" /tests/support.go /tests/verifier.go
/usr/local/go/bin/go build -trimpath -buildvcs=false -o "${bin_dir}/relayqd" ./cmd/relayqd
/usr/local/go/bin/go build -trimpath -buildvcs=false -o "${bin_dir}/relayctl" ./cmd/relayctl
/usr/local/go/bin/go build -trimpath -buildvcs=false -o "${bin_dir}/relayfixture" ./cmd/relayfixture
/usr/local/go/bin/go build -trimpath -buildvcs=false -o "${bin_dir}/relayinspect" ./cmd/relayinspect

# Candidate tests are code execution. Freeze the trusted sources and freshly
# built binaries before allowing that code to run, then execute it without
# privileges or access to verifier outputs.
chown -R 0:0 /app "${work_dir}"
chmod -R go-w /app "${work_dir}"
# Harbor may already provide /tests as a read-only root-owned mount. Tighten
# it when writable; the precompiled verifier remains authoritative either way.
chown -R 0:0 /tests >/dev/null 2>&1 || true
chmod -R go-w /tests >/dev/null 2>&1 || true
chmod 0555 "${work_dir}" "${bin_dir}" "${work_dir}/verifier" "${bin_dir}"/*

candidate_cache="${work_dir}/candidate-gocache"
candidate_gopath="${work_dir}/candidate-gopath"
candidate_tmp="${work_dir}/candidate-tmp"
install -d -m 0700 -o 65534 -g 65534 "${candidate_cache}" "${candidate_gopath}" "${candidate_tmp}"

/usr/bin/setpriv \
    --reuid=65534 --regid=65534 --clear-groups --no-new-privs \
    /usr/bin/env GOCACHE="${candidate_cache}" GOPATH="${candidate_gopath}" TMPDIR="${candidate_tmp}" \
    /usr/local/go/bin/go test -buildvcs=false -count=1 ./... \
    > /logs/verifier/unit-tests.log 2>&1

# A candidate test must not be able to leave a process racing the trusted
# integration phase after go test has returned.
/usr/bin/pkill -KILL -u 65534 >/dev/null 2>&1 || true

/usr/bin/setpriv \
    --reuid=65534 --regid=65534 --clear-groups --no-new-privs \
    "${work_dir}/verifier" -bin-dir "${bin_dir}" \
    > /logs/verifier/integration.log 2>&1
cat /logs/verifier/unit-tests.log
cat /logs/verifier/integration.log
reward=1
