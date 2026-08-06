# Durable Relay Starter

Durable Relay is an offline Go service that validates local chunk manifests,
assembles archive artifacts, persists job state in a framed WAL and snapshot,
and writes completion receipts. The repository intentionally starts in an
incident state: ordinary traffic works, while concurrency, reload, retry,
compaction, publication failure, and restart boundaries do not yet satisfy the
contract in `/app/../instruction.md` supplied by the task runner.

The project uses only the Go standard library.

```bash
go test ./...
make build
```

The four binaries are written to `bin/`: `relayqd`, `relayctl`,
`relayfixture`, and `relayinspect`. A local example configuration is available
at `configs/dev.json`. Do not add network dependencies.
