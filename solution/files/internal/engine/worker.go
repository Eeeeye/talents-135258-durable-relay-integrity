package engine

import (
	"fmt"
	"math"
	"time"

	"example.com/durable-relay/internal/model"
)

func (e *Engine) startWorkers(count int) {
	for index := 0; index < count; index++ {
		e.wg.Add(1)
		go e.worker(index)
	}
}

func (e *Engine) worker(_ int) {
	defer e.wg.Done()
	for {
		select {
		case <-e.ctx.Done():
			return
		case queued := <-e.queue:
			e.metrics.SetQueueDepth(len(e.queue))
			if queued.admitted != nil {
				select {
				case admitted := <-queued.admitted:
					if !admitted {
						continue
					}
				case <-e.ctx.Done():
					return
				}
			}
			if !e.acquireWorker() {
				return
			}
			e.metrics.WorkerEntered()
			e.process(queued.id)
			e.metrics.WorkerLeft()
			e.releaseWorker()
		}
	}
}

func (e *Engine) acquireWorker() bool {
	e.workerMu.Lock()
	defer e.workerMu.Unlock()
	for !e.closed.Load() && e.activeWorkers >= e.workerLimit {
		e.workerCond.Wait()
	}
	if e.closed.Load() {
		return false
	}
	e.activeWorkers++
	return true
}

func (e *Engine) releaseWorker() {
	e.workerMu.Lock()
	e.activeWorkers--
	e.workerCond.Broadcast()
	e.workerMu.Unlock()
}

func (e *Engine) setWorkerLimit(limit int) {
	e.workerMu.Lock()
	e.workerLimit = limit
	e.metrics.SetWorkerLimit(limit)
	e.workerCond.Broadcast()
	e.workerMu.Unlock()
}

func (e *Engine) process(id string) {
	job, ok := e.Get(id)
	if !ok || job.Terminal() {
		return
	}
	job.Status = model.StatusRunning
	job.Attempts++
	job.LastError = ""
	job.UpdatedAt = time.Now().UTC()
	if err := e.persist(model.EventStarted, job); err != nil {
		e.failInMemory(id, fmt.Sprintf("persist start: %v", err))
		return
	}
	e.metrics.Started()

	result, err := e.publisher.Publish(e.ctx, job.Spec.Manifest, job.Spec.Destination)
	if err != nil {
		e.handleAttemptFailure(job, err)
		return
	}
	job.Status = model.StatusSucceeded
	job.ArtifactSize = result.Size
	job.ArtifactSHA = result.SHA256
	job.LastError = ""
	job.UpdatedAt = time.Now().UTC()
	job.CompletedAt = job.UpdatedAt
	if err := e.persistSucceeded(job); err != nil {
		e.recordInMemoryError(id, fmt.Sprintf("persist success: %v", err))
		return
	}
	e.metrics.Succeeded()
}

func (e *Engine) handleAttemptFailure(job model.Job, cause error) {
	job.LastError = cause.Error()
	job.UpdatedAt = time.Now().UTC()
	if job.Attempts >= job.Spec.MaxAttempts || e.closed.Load() {
		job.Status = model.StatusFailed
		job.CompletedAt = job.UpdatedAt
		if err := e.persist(model.EventFailed, job); err != nil {
			e.failInMemory(job.ID, fmt.Sprintf("persist failure: %v", err))
			return
		}
		e.metrics.Failed()
		return
	}
	job.Status = model.StatusRetryWait
	if err := e.persist(model.EventRetry, job); err != nil {
		e.failInMemory(job.ID, fmt.Sprintf("persist retry: %v", err))
		return
	}
	e.metrics.Retried()
	delay := e.retryDelay(job.Attempts)
	e.wg.Add(1)
	go func(id string) {
		defer e.wg.Done()
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-e.ctx.Done():
			return
		case <-timer.C:
			_ = e.enqueue(id)
		}
	}(job.ID)
}

func (e *Engine) retryDelay(attempt int) time.Duration {
	exponent := attempt - 1
	if exponent < 0 {
		exponent = 0
	}
	if exponent > 8 {
		exponent = 8
	}
	multiplier := time.Duration(math.Pow(2, float64(exponent)))
	base := time.Duration(e.config.Current().RetryBaseMS) * time.Millisecond
	return base * multiplier
}

func (e *Engine) failInMemory(id, message string) {
	e.stateMu.Lock()
	job, ok := e.jobs[id]
	if ok {
		job.Status = model.StatusFailed
		job.LastError = message
		job.UpdatedAt = time.Now().UTC()
		job.CompletedAt = job.UpdatedAt
		e.jobs[id] = job
	}
	e.stateMu.Unlock()
}

func (e *Engine) recordInMemoryError(id, message string) {
	e.stateMu.Lock()
	job, ok := e.jobs[id]
	if ok {
		job.LastError = message
		job.UpdatedAt = time.Now().UTC()
		e.jobs[id] = job
	}
	e.stateMu.Unlock()
}
