package model

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

type JobStatus string

const (
	StatusPending   JobStatus = "pending"
	StatusRunning   JobStatus = "running"
	StatusRetryWait JobStatus = "retry_wait"
	StatusSucceeded JobStatus = "succeeded"
	StatusFailed    JobStatus = "failed"
)

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type JobSpec struct {
	RequestID   string `json:"request_id"`
	Manifest    string `json:"manifest"`
	Destination string `json:"destination"`
	MaxAttempts int    `json:"max_attempts,omitempty"`
}

func (s JobSpec) Validate(defaultAttempts int) (JobSpec, error) {
	s.RequestID = strings.TrimSpace(s.RequestID)
	s.Manifest = strings.TrimSpace(s.Manifest)
	s.Destination = strings.TrimSpace(s.Destination)
	if !requestIDPattern.MatchString(s.RequestID) {
		return JobSpec{}, errors.New("request_id must match [A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
	}
	if s.Manifest == "" {
		return JobSpec{}, errors.New("manifest is required")
	}
	if strings.IndexByte(s.Manifest, 0) >= 0 {
		return JobSpec{}, errors.New("manifest contains NUL")
	}
	if s.Destination == "" {
		return JobSpec{}, errors.New("destination is required")
	}
	if strings.IndexByte(s.Destination, 0) >= 0 {
		return JobSpec{}, errors.New("destination contains NUL")
	}
	if s.Manifest == s.Destination {
		return JobSpec{}, errors.New("manifest and destination must differ")
	}
	if s.MaxAttempts == 0 {
		s.MaxAttempts = defaultAttempts
	}
	if s.MaxAttempts < 1 || s.MaxAttempts > 20 {
		return JobSpec{}, fmt.Errorf("max_attempts must be between 1 and 20")
	}
	return s, nil
}

type Job struct {
	ID           string    `json:"id"`
	Spec         JobSpec   `json:"spec"`
	Status       JobStatus `json:"status"`
	Attempts     int       `json:"attempts"`
	LastError    string    `json:"last_error,omitempty"`
	ArtifactSize int64     `json:"artifact_size,omitempty"`
	ArtifactSHA  string    `json:"artifact_sha256,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	CompletedAt  time.Time `json:"completed_at,omitempty"`
}

func (j Job) Clone() Job {
	return j
}

func (j Job) Terminal() bool {
	return j.Status == StatusSucceeded || j.Status == StatusFailed
}

func (j Job) ValidateRecovered() error {
	if j.ID == "" {
		return errors.New("job id is empty")
	}
	if _, err := j.Spec.Validate(j.Spec.MaxAttempts); err != nil {
		return fmt.Errorf("job %s has invalid spec: %w", j.ID, err)
	}
	switch j.Status {
	case StatusPending, StatusRunning, StatusRetryWait, StatusSucceeded, StatusFailed:
	default:
		return fmt.Errorf("job %s has unknown status %q", j.ID, j.Status)
	}
	if j.Attempts < 0 || j.Attempts > j.Spec.MaxAttempts {
		return fmt.Errorf("job %s has invalid attempts %d", j.ID, j.Attempts)
	}
	if j.CreatedAt.IsZero() || j.UpdatedAt.IsZero() {
		return fmt.Errorf("job %s has missing timestamps", j.ID)
	}
	return nil
}

type SubmitResult struct {
	Job      Job  `json:"job"`
	Existing bool `json:"existing"`
}

type JobList struct {
	Jobs []Job `json:"jobs"`
}
