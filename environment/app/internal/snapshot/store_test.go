package snapshot

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"example.com/durable-relay/internal/model"
)

func TestSaveAndLoadSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	store := New(path)
	now := time.Now().UTC()
	job := model.Job{
		ID:        "job-snapshot",
		Spec:      model.JobSpec{RequestID: "request-snapshot", Manifest: "m", Destination: "d", MaxAttempts: 2},
		Status:    model.StatusPending,
		CreatedAt: now,
		UpdatedAt: now,
	}
	written := model.NewSnapshot(9, map[string]model.Job{job.ID: job}, now)
	if err := store.Save(written); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	loaded, exists, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !exists || loaded.LastSequence != 9 || len(loaded.Jobs) != 1 {
		t.Fatalf("unexpected loaded snapshot: %+v", loaded)
	}
}

func TestLoadRejectsTrailingJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(path, []byte(`{"version":1}{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := New(path).Load(); err == nil {
		t.Fatal("Load() unexpectedly accepted trailing JSON")
	}
}
