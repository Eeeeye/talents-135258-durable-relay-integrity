# Repair Durable Relay's cross-layer integrity guarantees

Durable Relay is a local artifact-delivery daemon used in an air-gapped HPC
workflow. A client submits a version-1 JSON manifest containing ordered local
chunks. The daemon validates and assembles the chunks into an archive path,
journals every job transition, periodically compacts state into a snapshot,
and appends a JSONL completion receipt.

The Starter builds and handles a simple delivery, but it is unsafe at reload,
concurrency, retry, publication-failure, compaction, and restart boundaries.
Repair the implementation in `/app` so every requirement below holds together.
Do not replace the service with a fixture-specific program or weaken existing
validation.

## 1. Transactional live reload

The configuration fields are divided into exactly these two groups:

- Live-mutable: `worker_count`, `retry_base_ms`, `max_attempts`, and
  `max_request_bytes`.
- Restart-required: `listen`, `state_dir`, `queue_capacity`, `sync_wal`,
  `snapshot_interval_ms`, and `shutdown_timeout_ms`.

A successful `POST /v1/admin/reload` must apply all live-mutable values before
the request completes and increment `generation` exactly once. New submissions
must use the new default attempt count and request-size limit, retry scheduling
must use the new base, and newly admitted work must use the new worker limit.
Scaling down must not cancel already-running work; after that work completes,
subsequent work must respect the lower limit. `/v1/stats` must report matching
configured and active worker limits after the reload returns.

Changing any restart-required field, or loading invalid/unknown/trailing JSON,
must return HTTP 409 from the reload endpoint. A rejected reload must preserve
the previous generation, published configuration, and runtime behavior.

## 2. Coherent WAL, snapshot, and compaction ordering

Keep the existing DRW1 version-1 format. Each frame is a 24-byte little-endian
header (magic, version, zero flags, payload length, CRC32-IEEE, and `uint64`
sequence) followed by one strict JSON event payload. Every accepted transition
must have one complete frame whose header and payload sequences agree.

Frame sequences must be unique and contiguous. Appending a frame, allocating
its sequence, publishing the corresponding in-memory state, capturing a
snapshot, and cutting over the WAL must have one coherent order even when jobs
and explicit compactions are concurrent. A snapshot must never be exposed
partially. If a post-snapshot WAL is nonempty, its first sequence must equal
`snapshot.json`'s `last_sequence + 1`, with every later sequence increasing by
exactly one. Concurrent submission and compaction must not lose any accepted
job across restart.

`sync_wal` retains its existing meaning for normal frame durability. Do not
change the DRW1 header, event schema, snapshot schema, or filenames
`events.wal` and `snapshot.json`.

## 3. Fail closed on durable-state damage

Startup may accept a missing or empty WAL and a clean frame boundary at EOF.
It must reject every other damaged journal, including a partial header or
payload, bad magic/version/flags/length, checksum failure, malformed or
invalid event JSON, a header/payload sequence mismatch, a non-contiguous
sequence, or a gap relative to the loaded snapshot.

On any such error, `relayqd` must exit nonzero and must never listen or report
ready. It must leave the damaged `events.wal` and `snapshot.json` bytes exactly
unchanged for diagnosis. Silently returning a decoded prefix with a warning is
not acceptable.

## 4. Atomic artifact publication

Before changing the requested final destination, validate every chunk's
existence, size, and lowercase SHA-256 as well as the total artifact size and
SHA-256. Any error or cancellation must:

- leave an absent destination absent;
- preserve a pre-existing destination byte-for-byte; and
- leave no abandoned publication temporary file in the destination directory.

On success, publish the exact concatenated bytes using a same-directory atomic
replacement and make the file and containing directory durable before reporting
success. Paths containing spaces are ordinary paths. A manifest containing one
or more zero-length chunks and an empty artifact is valid.

## 5. Durable request idempotency and exactly-one receipt

`request_id` is the durable idempotency key. The first valid submission owns the
key. Concurrent or later submissions whose normalized `manifest`,
`destination`, and effective `max_attempts` are identical must return the same
job with `existing:true` and HTTP 200. Only the first response creates the job
and uses HTTP 202.

Reusing a key with any different normalized value is an idempotency conflict:
return HTTP 409 with error code `idempotency_conflict`, create no job, and leave
the original unchanged. The key-to-job mapping must survive compaction and
restart. A successfully completed logical job must have exactly one valid
version-1 line in `receipts.jsonl`, including across concurrent duplicates,
retries, and restart recovery.

## 6. Preserve the public contract

Keep the commands `relayqd`, `relayctl`, `relayfixture`, and `relayinspect`,
their existing public flags, and these endpoints:

- `GET /v1/health`
- `GET /v1/stats`
- `POST /v1/jobs`
- `GET /v1/jobs?request_id=...`
- `GET /v1/jobs/{id}`
- `POST /v1/admin/reload`
- `POST /v1/admin/compact`

Keep the existing JSON field names, error envelope, strict unknown/trailing
JSON rejection, request-id grammar, manifest version and traversal protections,
configuration bounds/defaults, loopback-only listener rule, retry terminal
states, graceful shutdown, snapshot version, and receipt format. Continue to
bound request bodies. Do not trust or special-case particular paths, ports,
request IDs, hashes, counts, or timing values.

## 7. Working and acceptance conditions

Work inside `/app`. You may modify source, candidate-visible tests, and build
files there. Do not alter `/tests` or verifier logs. The environment has no
Internet access and requires no new dependency; use the Go standard library and
normal Linux filesystem/process facilities.

At minimum, keep these commands passing:

```bash
cd /app
go test ./...
make build
```

Acceptance uses fresh binaries and independently generated randomized fixtures,
temporary paths, and loopback ports. It observes HTTP results, process
readiness/exit, exact artifact bytes, destination preservation, temporary-file
hygiene, independent DRW1/CRC/sequence parsing, durable job identity, receipt
counts, live worker behavior, concurrent compaction, and restart recovery.
Candidate-generated logs or integrity summaries are not authoritative.
