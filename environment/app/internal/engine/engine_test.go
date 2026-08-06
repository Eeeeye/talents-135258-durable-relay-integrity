package engine

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"example.com/durable-relay/internal/config"
	"example.com/durable-relay/internal/fixture"
	"example.com/durable-relay/internal/model"
	"example.com/durable-relay/internal/wal"
)

func TestNormalDeliverySurvivesRestartAndCompaction(t *testing.T) {
	directory := t.TempDir()
	generated, err := fixture.Generate(fixture.Options{
		Root: filepath.Join(directory, "fixture"), Mode: fixture.ModeValid, Chunks: 3, ChunkSize: 4097, Seed: "engine-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(directory, "state")
	cfg := testConfig(stateDir)
	manager := config.NewManager(filepath.Join(directory, "unused.json"), cfg)
	opened, err := Open(manager)
	if err != nil {
		t.Fatal(err)
	}
	engine := opened.Engine
	destination := filepath.Join(directory, "archive", "result.bin")
	result, err := engine.Submit(model.JobSpec{
		RequestID: "normal-restart", Manifest: generated.Manifest, Destination: destination,
	})
	if err != nil {
		t.Fatal(err)
	}
	completed := waitForTerminal(t, engine, result.Job.ID)
	if completed.Status != model.StatusSucceeded || completed.ArtifactSHA != generated.ArtifactSHA256 {
		t.Fatalf("unexpected completed job: %+v", completed)
	}
	if err := engine.Compact(); err != nil {
		t.Fatalf("Compact() error = %v", err)
	}
	closeEngine(t, engine)

	if strict, err := wal.ScanStrict(filepath.Join(stateDir, "events.wal")); err != nil || strict.Records != 0 {
		t.Fatalf("WAL after compact = %+v, %v", strict, err)
	}
	reopened, err := Open(config.NewManager(filepath.Join(directory, "unused.json"), cfg))
	if err != nil {
		t.Fatal(err)
	}
	defer closeEngine(t, reopened.Engine)
	recovered, ok := reopened.Engine.Get(result.Job.ID)
	if !ok || recovered.Status != model.StatusSucceeded || recovered.ArtifactSHA != generated.ArtifactSHA256 {
		t.Fatalf("recovered job = %+v, ok=%v", recovered, ok)
	}
}

func TestFailedSingleAttemptReachesTerminalState(t *testing.T) {
	directory := t.TempDir()
	generated, err := fixture.Generate(fixture.Options{
		Root: filepath.Join(directory, "fixture"), Mode: fixture.ModeMissingLate, Chunks: 2, ChunkSize: 128, Seed: "failure-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(filepath.Join(directory, "state"))
	opened, err := Open(config.NewManager(filepath.Join(directory, "unused.json"), cfg))
	if err != nil {
		t.Fatal(err)
	}
	defer closeEngine(t, opened.Engine)
	result, err := opened.Engine.Submit(model.JobSpec{
		RequestID: "failure-terminal", Manifest: generated.Manifest,
		Destination: filepath.Join(directory, "archive", "failed.bin"), MaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	completed := waitForTerminal(t, opened.Engine, result.Job.ID)
	if completed.Status != model.StatusFailed || completed.Attempts != 1 || completed.LastError == "" {
		t.Fatalf("unexpected failed job: %+v", completed)
	}
}

func testConfig(stateDir string) config.Config {
	cfg := config.Default()
	cfg.Listen = "127.0.0.1:9999"
	cfg.StateDir = stateDir
	cfg.WorkerCount = 1
	cfg.RetryBaseMS = 5
	cfg.MaxAttempts = 2
	cfg.SnapshotIntervalMS = 0
	return cfg
}

func waitForTerminal(t *testing.T, engine *Engine, id string) model.Job {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		job, ok := engine.Get(id)
		if ok && job.Terminal() {
			return job
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("job %s did not finish", id)
	return model.Job{}
}

func closeEngine(t *testing.T, engine *Engine) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := engine.Close(ctx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}
