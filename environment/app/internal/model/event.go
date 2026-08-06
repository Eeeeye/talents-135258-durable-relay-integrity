package model

import (
	"errors"
	"fmt"
	"time"
)

type EventType string

const (
	EventSubmitted EventType = "job_submitted"
	EventStarted   EventType = "job_started"
	EventRetry     EventType = "job_retry"
	EventSucceeded EventType = "job_succeeded"
	EventFailed    EventType = "job_failed"
)

type Event struct {
	Sequence uint64    `json:"sequence"`
	Type     EventType `json:"type"`
	At       time.Time `json:"at"`
	Job      Job       `json:"job"`
}

func NewEvent(kind EventType, job Job, now time.Time) Event {
	return Event{Type: kind, At: now.UTC(), Job: job}
}

func (e Event) Validate() error {
	if e.Sequence == 0 {
		return errors.New("event sequence is zero")
	}
	if e.At.IsZero() {
		return errors.New("event time is zero")
	}
	switch e.Type {
	case EventSubmitted, EventStarted, EventRetry, EventSucceeded, EventFailed:
	default:
		return fmt.Errorf("unknown event type %q", e.Type)
	}
	if err := e.Job.ValidateRecovered(); err != nil {
		return err
	}
	return nil
}

type Snapshot struct {
	Version      int            `json:"version"`
	LastSequence uint64         `json:"last_sequence"`
	CreatedAt    time.Time      `json:"created_at"`
	Jobs         map[string]Job `json:"jobs"`
}

func NewSnapshot(sequence uint64, jobs map[string]Job, now time.Time) Snapshot {
	copyOfJobs := make(map[string]Job, len(jobs))
	for id, job := range jobs {
		copyOfJobs[id] = job.Clone()
	}
	return Snapshot{
		Version:      1,
		LastSequence: sequence,
		CreatedAt:    now.UTC(),
		Jobs:         copyOfJobs,
	}
}

func (s Snapshot) Validate() error {
	if s.Version != 1 {
		return fmt.Errorf("unsupported snapshot version %d", s.Version)
	}
	if s.CreatedAt.IsZero() {
		return errors.New("snapshot creation time is zero")
	}
	if s.Jobs == nil {
		return errors.New("snapshot jobs map is nil")
	}
	for id, job := range s.Jobs {
		if id != job.ID {
			return fmt.Errorf("snapshot key %q differs from job id %q", id, job.ID)
		}
		if err := job.ValidateRecovered(); err != nil {
			return err
		}
	}
	return nil
}

func ApplyEvent(jobs map[string]Job, event Event) error {
	if event.Type != EventSubmitted {
		if _, ok := jobs[event.Job.ID]; !ok {
			return fmt.Errorf("event %d references unknown job %q", event.Sequence, event.Job.ID)
		}
	}
	jobs[event.Job.ID] = event.Job.Clone()
	return nil
}
