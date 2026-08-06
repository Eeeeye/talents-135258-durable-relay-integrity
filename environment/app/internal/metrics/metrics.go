package metrics

import (
	"sync/atomic"
	"time"
)

type Counters struct {
	accepted          atomic.Uint64
	deduplicated      atomic.Uint64
	started           atomic.Uint64
	retried           atomic.Uint64
	succeeded         atomic.Uint64
	failed            atomic.Uint64
	walAppends        atomic.Uint64
	walBytes          atomic.Uint64
	snapshots         atomic.Uint64
	recoveryWarnings  atomic.Uint64
	activeWorkers     atomic.Int64
	activeWorkerLimit atomic.Int64
	queueDepth        atomic.Int64
	startedUnixNano   int64
}

type Snapshot struct {
	Accepted          uint64 `json:"accepted"`
	Deduplicated      uint64 `json:"deduplicated"`
	Started           uint64 `json:"started"`
	Retried           uint64 `json:"retried"`
	Succeeded         uint64 `json:"succeeded"`
	Failed            uint64 `json:"failed"`
	WALAppends        uint64 `json:"wal_appends"`
	WALBytes          uint64 `json:"wal_bytes"`
	Snapshots         uint64 `json:"snapshots"`
	RecoveryWarnings  uint64 `json:"recovery_warnings"`
	ActiveWorkers     int64  `json:"active_workers"`
	ActiveWorkerLimit int64  `json:"active_worker_limit"`
	QueueDepth        int64  `json:"queue_depth"`
	UptimeMS          int64  `json:"uptime_ms"`
}

func New() *Counters {
	return &Counters{startedUnixNano: time.Now().UnixNano()}
}

func (c *Counters) Accepted()        { c.accepted.Add(1) }
func (c *Counters) Deduplicated()    { c.deduplicated.Add(1) }
func (c *Counters) Started()         { c.started.Add(1) }
func (c *Counters) Retried()         { c.retried.Add(1) }
func (c *Counters) Succeeded()       { c.succeeded.Add(1) }
func (c *Counters) Failed()          { c.failed.Add(1) }
func (c *Counters) SnapshotCreated() { c.snapshots.Add(1) }
func (c *Counters) RecoveryWarning() { c.recoveryWarnings.Add(1) }

func (c *Counters) WALAppended(bytes int) {
	c.walAppends.Add(1)
	c.walBytes.Add(uint64(bytes))
}

func (c *Counters) WorkerEntered() { c.activeWorkers.Add(1) }
func (c *Counters) WorkerLeft()    { c.activeWorkers.Add(-1) }

func (c *Counters) SetWorkerLimit(limit int) {
	c.activeWorkerLimit.Store(int64(limit))
}

func (c *Counters) SetQueueDepth(depth int) {
	c.queueDepth.Store(int64(depth))
}

func (c *Counters) Read() Snapshot {
	return Snapshot{
		Accepted:          c.accepted.Load(),
		Deduplicated:      c.deduplicated.Load(),
		Started:           c.started.Load(),
		Retried:           c.retried.Load(),
		Succeeded:         c.succeeded.Load(),
		Failed:            c.failed.Load(),
		WALAppends:        c.walAppends.Load(),
		WALBytes:          c.walBytes.Load(),
		Snapshots:         c.snapshots.Load(),
		RecoveryWarnings:  c.recoveryWarnings.Load(),
		ActiveWorkers:     c.activeWorkers.Load(),
		ActiveWorkerLimit: c.activeWorkerLimit.Load(),
		QueueDepth:        c.queueDepth.Load(),
		UptimeMS:          (time.Now().UnixNano() - c.startedUnixNano) / int64(time.Millisecond),
	}
}
