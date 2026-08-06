package wal

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"example.com/durable-relay/internal/model"
)

func TestSequentialWriterRoundTripsStrictly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.wal")
	writer, err := OpenWriter(path, 1, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	job := validJob()
	for index, kind := range []model.EventType{model.EventSubmitted, model.EventStarted, model.EventSucceeded} {
		job.UpdatedAt = job.UpdatedAt.Add(time.Millisecond)
		if index == 1 {
			job.Status = model.StatusRunning
			job.Attempts = 1
		}
		if index == 2 {
			job.Status = model.StatusSucceeded
			job.CompletedAt = job.UpdatedAt
		}
		event := model.NewEvent(kind, job, job.UpdatedAt)
		if err := writer.AppendModel(&event); err != nil {
			t.Fatalf("append %d: %v", index, err)
		}
		if event.Sequence != uint64(index+1) {
			t.Fatalf("event sequence = %d", event.Sequence)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := ScanStrict(path)
	if err != nil {
		t.Fatalf("ScanStrict() error = %v", err)
	}
	if result.Records != 3 || result.LastSequence != 3 || len(result.Events) != 3 {
		t.Fatalf("unexpected scan: %+v", result)
	}
}

func TestStrictScanDistinguishesCleanEOFAndTruncation(t *testing.T) {
	directory := t.TempDir()
	empty := filepath.Join(directory, "empty.wal")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if result, err := ScanStrict(empty); err != nil || result.Records != 0 {
		t.Fatalf("clean empty scan = %+v, %v", result, err)
	}

	truncated := filepath.Join(directory, "truncated.wal")
	if err := os.WriteFile(truncated, []byte("DRW1"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ScanStrict(truncated)
	var corruption *CorruptionError
	if !errors.As(err, &corruption) || corruption.Offset != 0 {
		t.Fatalf("ScanStrict() error = %#v", err)
	}
}

func TestChecksumCorruptionIsReportedAtFrameOffset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.wal")
	writer, err := OpenWriter(path, 1, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	event := model.NewEvent(model.EventSubmitted, validJob(), time.Now())
	if err := writer.AppendModel(&event); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0x01
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = ScanStrict(path)
	var corruption *CorruptionError
	if !errors.As(err, &corruption) || corruption.Offset != 0 {
		t.Fatalf("ScanStrict() error = %#v", err)
	}
}

func validJob() model.Job {
	now := time.Now().UTC()
	return model.Job{
		ID: "job-test",
		Spec: model.JobSpec{
			RequestID: "request-test", Manifest: "manifest", Destination: "destination", MaxAttempts: 3,
		},
		Status:    model.StatusPending,
		CreatedAt: now,
		UpdatedAt: now,
	}
}
