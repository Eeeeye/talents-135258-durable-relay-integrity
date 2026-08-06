package model

import (
	"testing"
	"time"
)

func TestJobSpecDefaultsAndValidation(t *testing.T) {
	spec, err := (JobSpec{
		RequestID:   " campaign:007 ",
		Manifest:    " manifest.json ",
		Destination: " archive.bin ",
	}).Validate(4)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if spec.RequestID != "campaign:007" || spec.MaxAttempts != 4 {
		t.Fatalf("unexpected validated spec: %+v", spec)
	}
}

func TestJobSpecRejectsMalformedRequests(t *testing.T) {
	cases := []JobSpec{
		{RequestID: "", Manifest: "m", Destination: "d"},
		{RequestID: "bad request", Manifest: "m", Destination: "d"},
		{RequestID: "ok", Manifest: "", Destination: "d"},
		{RequestID: "ok", Manifest: "same", Destination: "same"},
		{RequestID: "ok", Manifest: "m", Destination: "d", MaxAttempts: 21},
	}
	for index, spec := range cases {
		if _, err := spec.Validate(3); err == nil {
			t.Fatalf("case %d unexpectedly succeeded: %+v", index, spec)
		}
	}
}

func TestApplyEventTracksLatestJob(t *testing.T) {
	now := time.Now().UTC()
	job := Job{
		ID:        "job-one",
		Spec:      JobSpec{RequestID: "request-one", Manifest: "m", Destination: "d", MaxAttempts: 3},
		Status:    StatusPending,
		CreatedAt: now,
		UpdatedAt: now,
	}
	event := NewEvent(EventSubmitted, job, now)
	event.Sequence = 1
	jobs := make(map[string]Job)
	if err := ApplyEvent(jobs, event); err != nil {
		t.Fatal(err)
	}
	job.Status = StatusRunning
	job.Attempts = 1
	job.UpdatedAt = now.Add(time.Second)
	event = NewEvent(EventStarted, job, job.UpdatedAt)
	event.Sequence = 2
	if err := ApplyEvent(jobs, event); err != nil {
		t.Fatal(err)
	}
	if observed := jobs[job.ID]; observed.Status != StatusRunning || observed.Attempts != 1 {
		t.Fatalf("unexpected job after event: %+v", observed)
	}
}

func TestSnapshotValidationRejectsKeyMismatch(t *testing.T) {
	now := time.Now().UTC()
	job := Job{
		ID:        "actual",
		Spec:      JobSpec{RequestID: "request", Manifest: "m", Destination: "d", MaxAttempts: 1},
		Status:    StatusPending,
		CreatedAt: now,
		UpdatedAt: now,
	}
	snapshot := NewSnapshot(1, map[string]Job{"wrong": job}, now)
	if err := snapshot.Validate(); err == nil {
		t.Fatal("snapshot key mismatch unexpectedly accepted")
	}
}
