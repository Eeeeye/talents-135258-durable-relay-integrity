package engine

import (
	"sort"
	"time"

	"example.com/durable-relay/internal/config"
	"example.com/durable-relay/internal/metrics"
	"example.com/durable-relay/internal/model"
)

type JobCounts struct {
	Pending   int `json:"pending"`
	Running   int `json:"running"`
	RetryWait int `json:"retry_wait"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
}

type Stats struct {
	Config           config.Snapshot  `json:"config"`
	Runtime          metrics.Snapshot `json:"runtime"`
	Jobs             JobCounts        `json:"jobs"`
	LastSequence     uint64           `json:"last_sequence"`
	RecoveryWarnings []string         `json:"recovery_warnings,omitempty"`
}

type Health struct {
	Ready            bool      `json:"ready"`
	ConfigGeneration uint64    `json:"config_generation"`
	RecoveredJobs    int       `json:"recovered_jobs"`
	RecoveryWarnings []string  `json:"recovery_warnings,omitempty"`
	CheckedAt        time.Time `json:"checked_at"`
}

func (e *Engine) Get(id string) (model.Job, bool) {
	e.stateMu.RLock()
	job, ok := e.jobs[id]
	e.stateMu.RUnlock()
	return job.Clone(), ok
}

func (e *Engine) ListByRequest(requestID string) []model.Job {
	e.stateMu.RLock()
	jobs := make([]model.Job, 0)
	for _, job := range e.jobs {
		if job.Spec.RequestID == requestID {
			jobs = append(jobs, job.Clone())
		}
	}
	e.stateMu.RUnlock()
	sort.Slice(jobs, func(i, j int) bool {
		if jobs[i].CreatedAt.Equal(jobs[j].CreatedAt) {
			return jobs[i].ID < jobs[j].ID
		}
		return jobs[i].CreatedAt.Before(jobs[j].CreatedAt)
	})
	return jobs
}

func (e *Engine) Stats() Stats {
	e.stateMu.RLock()
	var counts JobCounts
	for _, job := range e.jobs {
		switch job.Status {
		case model.StatusPending:
			counts.Pending++
		case model.StatusRunning:
			counts.Running++
		case model.StatusRetryWait:
			counts.RetryWait++
		case model.StatusSucceeded:
			counts.Succeeded++
		case model.StatusFailed:
			counts.Failed++
		}
	}
	last := e.lastSequence
	warnings := append([]string(nil), e.warnings...)
	e.stateMu.RUnlock()
	return Stats{
		Config:           e.config.Current(),
		Runtime:          e.metrics.Read(),
		Jobs:             counts,
		LastSequence:     last,
		RecoveryWarnings: warnings,
	}
}

func (e *Engine) Health() Health {
	e.stateMu.RLock()
	count := len(e.jobs)
	warnings := append([]string(nil), e.warnings...)
	e.stateMu.RUnlock()
	return Health{
		Ready:            !e.closed.Load(),
		ConfigGeneration: e.config.Current().Generation,
		RecoveredJobs:    count,
		RecoveryWarnings: warnings,
		CheckedAt:        time.Now().UTC(),
	}
}

func (e *Engine) Reload() (config.Snapshot, error) {
	return e.config.Reload()
}

func (e *Engine) WorkerLimit() int {
	return e.workerLimit
}
