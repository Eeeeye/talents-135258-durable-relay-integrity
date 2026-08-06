package engine

import (
	"fmt"
	"time"

	"example.com/durable-relay/internal/model"
)

func (e *Engine) Compact() error {
	if e.closed.Load() {
		return ErrClosed
	}
	e.durabilityMu.Lock()
	defer e.durabilityMu.Unlock()
	e.stateMu.RLock()
	snapshot := model.NewSnapshot(e.lastSequence, e.jobs, time.Now())
	e.stateMu.RUnlock()

	if err := e.snapshot.Save(snapshot); err != nil {
		return fmt.Errorf("save snapshot: %w", err)
	}
	if err := e.wal.Truncate(); err != nil {
		return fmt.Errorf("rotate WAL: %w", err)
	}
	e.metrics.SnapshotCreated()
	return nil
}

func (e *Engine) startCompactor(interval time.Duration) {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-e.ctx.Done():
				return
			case <-ticker.C:
				_ = e.Compact()
			}
		}
	}()
}
