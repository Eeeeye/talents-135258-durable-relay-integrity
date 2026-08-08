#!/bin/bash
set -Eeuo pipefail

umask 077
install -d -m 0755 /logs/verifier
reward=0
unit_group_pid=""
cleanup_unit_group() {
    if [[ -n "${unit_group_pid}" ]]; then
        kill -KILL -- "-${unit_group_pid}" >/dev/null 2>&1 || true
        wait "${unit_group_pid}" >/dev/null 2>&1 || true
        unit_group_pid=""
    fi
}
finish() {
    cleanup_unit_group
    printf '%s\n' "${reward}" > /logs/verifier/reward.txt
    chmod 0644 /logs/verifier/reward.txt
}
trap finish EXIT

export GOPROXY=off
export GOSUMDB=off
export GOTOOLCHAIN=local
export GOFLAGS=-mod=readonly
export CGO_ENABLED=0

work_dir="$(mktemp -d /tmp/.XXXXXXXXXXXX)"
bin_dir="${work_dir}/bin"
root_cache="${work_dir}/root-gocache"
install -d -m 0700 "${bin_dir}" "${root_cache}"
export GOCACHE="${root_cache}"
export GOPATH="${work_dir}/root-gopath"

cd /app
if /bin/grep -R -n -E 'Gete?uid|DURABLE_RELAY_TEST_SEED|durable-relay-(integration|verifier)|candidate_uid' \
    --include='*.go' --exclude-dir='.git' . > /logs/verifier/environment-fingerprint.log; then
    cat /logs/verifier/environment-fingerprint.log
    printf '%s\n' 'candidate source contains a verifier-environment fingerprint' >&2
    exit 1
fi
/usr/local/go/bin/go build -trimpath -buildvcs=false -o "${work_dir}/verifier" /tests/support.go /tests/verifier.go
/usr/local/go/bin/go build -trimpath -buildvcs=false -o "${bin_dir}/relayqd" ./cmd/relayqd
/usr/local/go/bin/go build -trimpath -buildvcs=false -o "${bin_dir}/relayctl" ./cmd/relayctl
/usr/local/go/bin/go build -trimpath -buildvcs=false -o "${bin_dir}/relayfixture" ./cmd/relayfixture
/usr/local/go/bin/go build -trimpath -buildvcs=false -o "${bin_dir}/relayinspect" ./cmd/relayinspect

# Freeze the trusted sources and freshly built binaries before executing any
# candidate-controlled code.
chown -R 0:0 /app "${work_dir}"
chmod -R go-w /app "${work_dir}"
# Some remote Harbor backends expose /tests as a read-only root-owned mount.
# The trusted verifier has already been compiled and runs before any candidate
# test code, so tightening this source tree is defense in depth and must remain
# best-effort on those backends.
chown -R 0:0 /tests >/dev/null 2>&1 || true
chmod -R u=rwX,go= /tests >/dev/null 2>&1 || true
chmod 0711 "${work_dir}" "${bin_dir}"
chmod 0500 "${work_dir}/verifier"
chmod 0555 "${bin_dir}"/*

# Run the trusted integration phase first. Candidate tests are arbitrary code;
# placing them last prevents a detached test process from observing or racing
# verifier-created services, fixtures, state, or timing windows.
"${work_dir}/verifier" -bin-dir "${bin_dir}" \
    > /logs/verifier/integration.log 2>&1

candidate_cache="${work_dir}/candidate-gocache"
candidate_gopath="${work_dir}/candidate-gopath"
candidate_tmp="${work_dir}/candidate-tmp"
candidate_unit_uid=59999
candidate_unit_gid=59999
install -d -m 0700 -o "${candidate_unit_uid}" -g "${candidate_unit_gid}" \
    "${candidate_cache}" "${candidate_gopath}" "${candidate_tmp}"

set +e
/usr/bin/setsid /usr/bin/setpriv \
    --reuid="${candidate_unit_uid}" --regid="${candidate_unit_gid}" --clear-groups --no-new-privs \
    /usr/bin/env GOCACHE="${candidate_cache}" GOPATH="${candidate_gopath}" TMPDIR="${candidate_tmp}" \
    /usr/local/go/bin/go test -buildvcs=false -count=1 ./... \
    > /logs/verifier/unit-tests.log 2>&1 &
unit_group_pid=$!
wait "${unit_group_pid}"
unit_status=$?
set -e
cleanup_unit_group
if (( unit_status != 0 )); then
    cat /logs/verifier/unit-tests.log
    exit "${unit_status}"
fi

cat /logs/verifier/integration.log
cat /logs/verifier/unit-tests.log
reward=1
