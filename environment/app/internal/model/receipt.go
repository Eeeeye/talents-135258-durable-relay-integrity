package model

import "time"

type Receipt struct {
	Version        int       `json:"version"`
	JobID          string    `json:"job_id"`
	RequestID      string    `json:"request_id"`
	Destination    string    `json:"destination"`
	ArtifactSize   int64     `json:"artifact_size"`
	ArtifactSHA256 string    `json:"artifact_sha256"`
	CompletedAt    time.Time `json:"completed_at"`
}

func NewReceipt(job Job) Receipt {
	return Receipt{
		Version:        1,
		JobID:          job.ID,
		RequestID:      job.Spec.RequestID,
		Destination:    job.Spec.Destination,
		ArtifactSize:   job.ArtifactSize,
		ArtifactSHA256: job.ArtifactSHA,
		CompletedAt:    job.CompletedAt.UTC(),
	}
}
