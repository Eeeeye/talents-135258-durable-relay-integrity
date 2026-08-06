package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"example.com/durable-relay/internal/config"
	"example.com/durable-relay/internal/ledger"
	"example.com/durable-relay/internal/metrics"
	"example.com/durable-relay/internal/model"
	"example.com/durable-relay/internal/publisher"
	"example.com/durable-relay/internal/snapshot"
	"example.com/durable-relay/internal/wal"
)

var (
	ErrClosed              = errors.New("engine is closed")
	ErrNotFound            = errors.New("job not found")
	ErrQueueFull           = errors.New("job queue is full")
	ErrIdempotencyConflict = errors.New("idempotency key conflicts with the existing job")
)

type Engine struct {
	config    *config.Manager
	metrics   *metrics.Counters
	wal       *wal.Writer
	snapshot  *snapshot.Store
	ledger    *ledger.Ledger
	publisher *publisher.Publisher

	durabilityMu sync.Mutex
	submitMu     sync.Mutex
	reloadMu     sync.RWMutex
	stateMu      sync.RWMutex
	jobs         map[string]model.Job
	requests     map[string]string
	lastSequence uint64
	warnings     []string

	queue         chan string
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	closed        atomic.Bool
	workerMu      sync.Mutex
	workerCond    *sync.Cond
	workerLimit   int
	activeWorkers int
}

type OpenResult struct {
	Engine          *Engine
	RecoveredJobs   int
	RecoveredEvents int
	Warnings        []string
}

func Open(manager *config.Manager) (OpenResult, error) {
	current := manager.Current()
	if err := os.MkdirAll(current.StateDir, 0o700); err != nil {
		return OpenResult{}, fmt.Errorf("create state directory: %w", err)
	}
	if err := os.Chmod(current.StateDir, 0o700); err != nil {
		return OpenResult{}, fmt.Errorf("protect state directory: %w", err)
	}

	snapshotStore := snapshot.New(filepath.Join(current.StateDir, "snapshot.json"))
	jobs := make(map[string]model.Job)
	var lastSequence uint64
	loaded, exists, err := snapshotStore.Load()
	if err != nil {
		return OpenResult{}, err
	}
	if exists {
		for id, job := range loaded.Jobs {
			jobs[id] = job.Clone()
		}
		lastSequence = loaded.LastSequence
	}

	walPath := filepath.Join(current.StateDir, "events.wal")
	recovery, err := wal.Recover(walPath)
	if err != nil {
		return OpenResult{}, err
	}
	if len(recovery.Events) > 0 && recovery.Events[0].Sequence != lastSequence+1 {
		return OpenResult{}, fmt.Errorf("WAL begins at sequence %d after durable sequence %d", recovery.Events[0].Sequence, lastSequence)
	}
	for _, event := range recovery.Events {
		if event.Sequence != lastSequence+1 {
			return OpenResult{}, fmt.Errorf("WAL sequence %d does not follow durable sequence %d", event.Sequence, lastSequence)
		}
		if err := model.ApplyEvent(jobs, event); err != nil {
			return OpenResult{}, fmt.Errorf("apply recovered event %d: %w", event.Sequence, err)
		}
		lastSequence = event.Sequence
	}
	requests := make(map[string]string, len(jobs))
	for id, job := range jobs {
		if previous, ok := requests[job.Spec.RequestID]; ok && previous != id {
			return OpenResult{}, fmt.Errorf("durable idempotency conflict for request_id %q: jobs %q and %q", job.Spec.RequestID, previous, id)
		}
		requests[job.Spec.RequestID] = id
	}

	counters := metrics.New()
	for range recovery.Warnings {
		counters.RecoveryWarning()
	}
	writer, err := wal.OpenWriter(walPath, lastSequence+1, current.SyncWAL, counters.WALAppended)
	if err != nil {
		return OpenResult{}, err
	}
	receiptLedger, err := ledger.Open(filepath.Join(current.StateDir, "receipts.jsonl"))
	if err != nil {
		writer.Close()
		return OpenResult{}, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	engine := &Engine{
		config:       manager,
		metrics:      counters,
		wal:          writer,
		snapshot:     snapshotStore,
		ledger:       receiptLedger,
		publisher:    publisher.New(),
		jobs:         jobs,
		requests:     requests,
		lastSequence: lastSequence,
		warnings:     append([]string(nil), recovery.Warnings...),
		queue:        make(chan string, current.QueueCapacity),
		ctx:          ctx,
		cancel:       cancel,
		workerLimit:  current.WorkerCount,
	}
	engine.workerCond = sync.NewCond(&engine.workerMu)
	ids := make([]string, 0, len(jobs))
	for id := range jobs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if jobs[id].Status == model.StatusSucceeded {
			if err := receiptLedger.Append(model.NewReceipt(jobs[id])); err != nil {
				writer.Close()
				receiptLedger.Close()
				cancel()
				return OpenResult{}, fmt.Errorf("reconcile receipt for job %s: %w", id, err)
			}
		}
	}
	engine.metrics.SetWorkerLimit(current.WorkerCount)
	engine.startWorkers(64)
	engine.enqueueRecovered()
	if current.SnapshotIntervalMS > 0 {
		engine.startCompactor(time.Duration(current.SnapshotIntervalMS) * time.Millisecond)
	}
	return OpenResult{
		Engine:          engine,
		RecoveredJobs:   len(jobs),
		RecoveredEvents: len(recovery.Events),
		Warnings:        append([]string(nil), recovery.Warnings...),
	}, nil
}

func (e *Engine) Submit(spec model.JobSpec) (model.SubmitResult, error) {
	e.submitMu.Lock()
	defer e.submitMu.Unlock()
	if e.closed.Load() {
		return model.SubmitResult{}, ErrClosed
	}
	current := e.config.Current()
	validated, err := spec.Validate(current.MaxAttempts)
	if err != nil {
		return model.SubmitResult{}, err
	}
	e.stateMu.RLock()
	existingID, exists := e.requests[validated.RequestID]
	existing := e.jobs[existingID]
	e.stateMu.RUnlock()
	if exists {
		if existing.Spec != validated {
			return model.SubmitResult{}, fmt.Errorf("%w: request_id %q belongs to job %q", ErrIdempotencyConflict, validated.RequestID, existing.ID)
		}
		e.metrics.Deduplicated()
		return model.SubmitResult{Job: existing.Clone(), Existing: true}, nil
	}
	now := time.Now().UTC()
	job := model.Job{
		ID:        newJobID(now),
		Spec:      validated,
		Status:    model.StatusPending,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := e.persist(model.EventSubmitted, job); err != nil {
		return model.SubmitResult{}, err
	}
	e.metrics.Accepted()
	if err := e.enqueue(job.ID); err != nil {
		return model.SubmitResult{Job: job}, err
	}
	return model.SubmitResult{Job: job, Existing: false}, nil
}

func (e *Engine) persist(kind model.EventType, job model.Job) error {
	e.durabilityMu.Lock()
	defer e.durabilityMu.Unlock()
	event := model.NewEvent(kind, job, time.Now())
	if err := e.wal.AppendModel(&event); err != nil {
		return err
	}
	e.stateMu.Lock()
	e.jobs[job.ID] = job.Clone()
	if kind == model.EventSubmitted {
		e.requests[job.Spec.RequestID] = job.ID
	}
	if event.Sequence > e.lastSequence {
		e.lastSequence = event.Sequence
	}
	e.stateMu.Unlock()
	return nil
}

func (e *Engine) enqueue(id string) error {
	select {
	case <-e.ctx.Done():
		return ErrClosed
	case e.queue <- id:
		e.metrics.SetQueueDepth(len(e.queue))
		return nil
	default:
		return ErrQueueFull
	}
}

func (e *Engine) enqueueRecovered() {
	e.stateMu.Lock()
	ids := make([]string, 0, len(e.jobs))
	for id, job := range e.jobs {
		if job.Terminal() {
			continue
		}
		job.Status = model.StatusPending
		job.UpdatedAt = time.Now().UTC()
		e.jobs[id] = job
		ids = append(ids, id)
	}
	e.stateMu.Unlock()
	sort.Strings(ids)
	for _, id := range ids {
		_ = e.enqueue(id)
	}
}

func newJobID(now time.Time) string {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return fmt.Sprintf("job-%d-%s", now.UnixMilli(), hex.EncodeToString(random))
}

func (e *Engine) Close(ctx context.Context) error {
	if !e.closed.CompareAndSwap(false, true) {
		return nil
	}
	e.cancel()
	e.workerMu.Lock()
	e.workerCond.Broadcast()
	e.workerMu.Unlock()
	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	var joined error
	if err := e.wal.Sync(); err != nil {
		joined = errors.Join(joined, err)
	}
	if err := e.wal.Close(); err != nil {
		joined = errors.Join(joined, err)
	}
	if err := e.ledger.Close(); err != nil {
		joined = errors.Join(joined, err)
	}
	return joined
}
