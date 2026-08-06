package main

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	binDir := flag.String("bin-dir", "", "directory containing freshly built relay binaries")
	flag.Parse()
	if *binDir == "" {
		fmt.Fprintln(os.Stderr, "verifier: -bin-dir is required")
		os.Exit(2)
	}
	seed, err := verifierSeed()
	if err != nil {
		fmt.Fprintf(os.Stderr, "verifier: choose seed: %v\n", err)
		os.Exit(2)
	}
	root, err := os.MkdirTemp("", "durable-relay-integration-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "verifier: temp root: %v\n", err)
		os.Exit(2)
	}
	if os.Getenv("DURABLE_RELAY_KEEP_TMP") == "" {
		defer os.RemoveAll(root)
	} else {
		fmt.Printf("verifier preserving temp root=%s\n", root)
	}
	v := &verifier{binDir: *binDir, root: root, seed: seed, rng: rand.New(rand.NewSource(seed))}

	tests := []struct {
		name string
		run  func(*verifier) error
	}{
		{"ordinary-and-atomic-publication", testOrdinaryAndAtomicPublication},
		{"durable-idempotency", testDurableIdempotency},
		{"transactional-live-reload", testTransactionalReload},
		{"concurrent-wal-compaction-restart", testConcurrentWALCompaction},
		{"corrupt-state-fails-closed", testCorruptionFailsClosed},
	}

	fmt.Printf("verifier seed=%d root=%s\n", seed, root)
	for _, test := range tests {
		started := time.Now()
		fmt.Printf("RUN  %s\n", test.name)
		if err := test.run(v); err != nil {
			fmt.Printf("FAIL %s (%s): %v\n", test.name, time.Since(started).Round(time.Millisecond), err)
			fmt.Printf("reproduce with DURABLE_RELAY_TEST_SEED=%d\n", seed)
			os.Exit(1)
		}
		fmt.Printf("PASS %s (%s)\n", test.name, time.Since(started).Round(time.Millisecond))
	}
	fmt.Printf("all integration checks passed; seed=%d\n", seed)
}

func verifierSeed() (int64, error) {
	if configured := os.Getenv("DURABLE_RELAY_TEST_SEED"); configured != "" {
		value, err := strconv.ParseInt(configured, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid DURABLE_RELAY_TEST_SEED: %w", err)
		}
		return value, nil
	}
	var raw [8]byte
	if _, err := cryptorand.Read(raw[:]); err != nil {
		return 0, err
	}
	return int64(binary.LittleEndian.Uint64(raw[:]) & ((1 << 63) - 1)), nil
}

func testOrdinaryAndAtomicPublication(v *verifier) error {
	directory := filepath.Join(v.root, "ordinary atomic")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	cfg := baseConfig()
	cfg.WorkerCount = 3
	cfg.MaxAttempts = 2
	configPath, cfg, err := v.prepareConfig(directory, cfg)
	if err != nil {
		return err
	}
	svc, err := startService(v.binDir, configPath, cfg.Listen, filepath.Join(directory, "logs"))
	if err != nil {
		return err
	}
	defer svc.kill()

	valid, err := v.makeFixture(directory, "valid fixture", [][]byte{nil, v.bytes(37), v.bytes(131137)})
	if err != nil {
		return err
	}
	destination := filepath.Join(directory, "archive with spaces", "result artifact.bin")
	requestID := v.token("ordinary")
	status, submitted, raw, err := svc.submit(jobSpec{RequestID: requestID, Manifest: valid.Manifest, Destination: destination})
	if err != nil {
		return err
	}
	if status != http.StatusAccepted || submitted.Existing || submitted.Job.ID == "" {
		return fmt.Errorf("ordinary submit status=%d result=%+v body=%s", status, submitted, strings.TrimSpace(string(raw)))
	}
	completed, err := waitTerminal(svc, submitted.Job.ID, 8*time.Second)
	if err != nil {
		return err
	}
	if completed.Status != "succeeded" || completed.ArtifactSize != valid.ArtifactSize || completed.ArtifactSHA != valid.ArtifactSHA {
		return fmt.Errorf("ordinary completion mismatch: %+v", completed)
	}
	observed, err := os.ReadFile(destination)
	if err != nil {
		return err
	}
	if !bytes.Equal(observed, valid.Artifact) {
		return fmt.Errorf("ordinary artifact bytes differ: got=%d expected=%d", len(observed), len(valid.Artifact))
	}

	zero, err := v.makeFixture(directory, "zero fixture", [][]byte{nil, nil})
	if err != nil {
		return err
	}
	zeroDestination := filepath.Join(directory, "zero archive", "empty output.bin")
	status, zeroSubmit, raw, err := svc.submit(jobSpec{
		RequestID: v.token("zero"), Manifest: zero.Manifest, Destination: zeroDestination,
	})
	if err != nil || status != http.StatusAccepted {
		return fmt.Errorf("zero submit status=%d err=%v body=%s", status, err, strings.TrimSpace(string(raw)))
	}
	zeroJob, err := waitTerminal(svc, zeroSubmit.Job.ID, 5*time.Second)
	if err != nil {
		return err
	}
	if zeroJob.Status != "succeeded" || zeroJob.ArtifactSize != 0 {
		return fmt.Errorf("zero artifact did not succeed: %+v", zeroJob)
	}
	zeroBytes, err := os.ReadFile(zeroDestination)
	if err != nil || len(zeroBytes) != 0 {
		return fmt.Errorf("zero output invalid: size=%d err=%v", len(zeroBytes), err)
	}

	missing, err := v.makeFixture(directory, "missing late fixture", [][]byte{v.bytes(8193), v.bytes(4099)})
	if err != nil {
		return err
	}
	if err := os.Remove(missing.ChunkPaths[1]); err != nil {
		return err
	}
	existingDir := filepath.Join(directory, "existing destination")
	if err := os.MkdirAll(existingDir, 0o700); err != nil {
		return err
	}
	existingDestination := filepath.Join(existingDir, "preserve me.bin")
	sentinel := append([]byte("pre-existing:"), v.bytes(257)...)
	if err := os.WriteFile(existingDestination, sentinel, 0o640); err != nil {
		return err
	}
	status, failedSubmit, raw, err := svc.submit(jobSpec{
		RequestID: v.token("missing"), Manifest: missing.Manifest,
		Destination: existingDestination, MaxAttempts: 1,
	})
	if err != nil || status != http.StatusAccepted {
		return fmt.Errorf("missing submit status=%d err=%v body=%s", status, err, strings.TrimSpace(string(raw)))
	}
	failed, err := waitTerminal(svc, failedSubmit.Job.ID, 5*time.Second)
	if err != nil {
		return err
	}
	if failed.Status != "failed" || failed.Attempts != 1 {
		return fmt.Errorf("missing job did not fail once: %+v", failed)
	}
	preserved, err := os.ReadFile(existingDestination)
	if err != nil || !bytes.Equal(preserved, sentinel) {
		return fmt.Errorf("pre-existing destination changed: err=%v got=%d", err, len(preserved))
	}
	entries, err := directoryNames(existingDir)
	if err != nil || len(entries) != 1 || entries[0] != filepath.Base(existingDestination) {
		return fmt.Errorf("publication temp residue beside existing target: entries=%v err=%v", entries, err)
	}

	corrupt, err := v.makeFixture(directory, "corrupt late fixture", [][]byte{v.bytes(4097), v.bytes(8195)})
	if err != nil {
		return err
	}
	corruptBytes := append([]byte(nil), corrupt.ChunkData[1]...)
	corruptBytes[len(corruptBytes)/2] ^= 0x80
	if err := os.WriteFile(corrupt.ChunkPaths[1], corruptBytes, 0o600); err != nil {
		return err
	}
	absentDir := filepath.Join(directory, "absent destination")
	absentDestination := filepath.Join(absentDir, "must stay absent.bin")
	status, corruptSubmit, raw, err := svc.submit(jobSpec{
		RequestID: v.token("corrupt"), Manifest: corrupt.Manifest,
		Destination: absentDestination, MaxAttempts: 1,
	})
	if err != nil || status != http.StatusAccepted {
		return fmt.Errorf("corrupt submit status=%d err=%v body=%s", status, err, strings.TrimSpace(string(raw)))
	}
	corruptJob, err := waitTerminal(svc, corruptSubmit.Job.ID, 5*time.Second)
	if err != nil {
		return err
	}
	if corruptJob.Status != "failed" {
		return fmt.Errorf("corrupt job unexpectedly succeeded: %+v", corruptJob)
	}
	if _, err := os.Stat(absentDestination); !os.IsNotExist(err) {
		return fmt.Errorf("failed publication created absent destination: err=%v", err)
	}
	entries, err = directoryNames(absentDir)
	if err != nil || len(entries) != 0 {
		return fmt.Errorf("publication temp residue beside absent target: entries=%v err=%v", entries, err)
	}

	if err := svc.stop(); err != nil {
		return fmt.Errorf("ordinary service shutdown: %w", err)
	}
	return nil
}

func testDurableIdempotency(v *verifier) error {
	directory := filepath.Join(v.root, "durable idempotency")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	cfg := baseConfig()
	cfg.WorkerCount = 6
	configPath, cfg, err := v.prepareConfig(directory, cfg)
	if err != nil {
		return err
	}
	svc, err := startService(v.binDir, configPath, cfg.Listen, filepath.Join(directory, "logs-one"))
	if err != nil {
		return err
	}
	defer svc.kill()
	generated, err := v.makeFixture(directory, "idempotent fixture", [][]byte{v.bytes(12003), v.bytes(9017)})
	if err != nil {
		return err
	}
	spec := jobSpec{
		RequestID: v.token("same-key"), Manifest: generated.Manifest,
		Destination: filepath.Join(directory, "archive", "idempotent.bin"),
	}

	const submissions = 24
	type outcome struct {
		status int
		result submitResult
		raw    []byte
		err    error
	}
	outcomes := make([]outcome, submissions)
	start := make(chan struct{})
	var group sync.WaitGroup
	for index := range outcomes {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			<-start
			outcomes[index].status, outcomes[index].result, outcomes[index].raw, outcomes[index].err = svc.submit(spec)
		}(index)
	}
	close(start)
	group.Wait()

	var jobID string
	created := 0
	existing := 0
	for index, outcome := range outcomes {
		if outcome.err != nil {
			return fmt.Errorf("duplicate submit %d: %w", index, outcome.err)
		}
		if outcome.status == http.StatusAccepted && !outcome.result.Existing {
			created++
		} else if outcome.status == http.StatusOK && outcome.result.Existing {
			existing++
		} else {
			return fmt.Errorf("duplicate submit %d status=%d result=%+v body=%s", index, outcome.status, outcome.result, strings.TrimSpace(string(outcome.raw)))
		}
		if jobID == "" {
			jobID = outcome.result.Job.ID
		}
		if outcome.result.Job.ID != jobID {
			return fmt.Errorf("one idempotency key returned different jobs: %s and %s", jobID, outcome.result.Job.ID)
		}
	}
	if created != 1 || existing != submissions-1 {
		return fmt.Errorf("duplicate response split created=%d existing=%d", created, existing)
	}
	completed, err := waitTerminal(svc, jobID, 8*time.Second)
	if err != nil {
		return err
	}
	if completed.Status != "succeeded" {
		return fmt.Errorf("idempotent job failed: %+v", completed)
	}
	listed, err := svc.listByRequest(spec.RequestID)
	if err != nil || len(listed) != 1 || listed[0].ID != jobID {
		return fmt.Errorf("idempotent list=%+v err=%v", listed, err)
	}
	receipts, err := readReceipts(filepath.Join(cfg.StateDir, "receipts.jsonl"))
	if err != nil {
		return err
	}
	count := 0
	for _, value := range receipts {
		if value.RequestID == spec.RequestID {
			count++
			if value.JobID != jobID || value.ArtifactSHA256 != generated.ArtifactSHA {
				return fmt.Errorf("idempotent receipt mismatch: %+v", value)
			}
		}
	}
	if count != 1 {
		return fmt.Errorf("idempotent request has %d receipts, expected 1", count)
	}

	conflict := spec
	conflict.Destination = filepath.Join(directory, "archive", "conflicting.bin")
	status, _, raw, err := svc.submit(conflict)
	if err != nil {
		return err
	}
	var envelope errorEnvelope
	_ = json.Unmarshal(raw, &envelope)
	if status != http.StatusConflict || envelope.Error.Code != "idempotency_conflict" {
		return fmt.Errorf("conflict status=%d code=%q body=%s", status, envelope.Error.Code, strings.TrimSpace(string(raw)))
	}
	listed, err = svc.listByRequest(spec.RequestID)
	if err != nil || len(listed) != 1 || listed[0].ID != jobID {
		return fmt.Errorf("conflict changed original job: jobs=%+v err=%v", listed, err)
	}

	status, raw, err = svc.requestJSON(http.MethodPost, "/v1/admin/compact", nil)
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("compact before restart status=%d err=%v body=%s", status, err, strings.TrimSpace(string(raw)))
	}
	if err := svc.stop(); err != nil {
		return err
	}

	address, err := reserveAddress()
	if err != nil {
		return err
	}
	cfg.Listen = address
	if err := writeJSON(configPath, cfg); err != nil {
		return err
	}
	restarted, err := startService(v.binDir, configPath, cfg.Listen, filepath.Join(directory, "logs-two"))
	if err != nil {
		return err
	}
	defer restarted.kill()
	status, replay, raw, err := restarted.submit(spec)
	if err != nil || status != http.StatusOK || !replay.Existing || replay.Job.ID != jobID {
		return fmt.Errorf("restart duplicate status=%d result=%+v err=%v body=%s", status, replay, err, strings.TrimSpace(string(raw)))
	}
	receipts, err = readReceipts(filepath.Join(cfg.StateDir, "receipts.jsonl"))
	if err != nil {
		return err
	}
	count = 0
	for _, value := range receipts {
		if value.RequestID == spec.RequestID {
			count++
		}
	}
	if count != 1 {
		return fmt.Errorf("restart changed receipt count to %d", count)
	}
	if err := restarted.stop(); err != nil {
		return err
	}
	return nil
}

type fifoOpenResult struct {
	path string
	file *os.File
	err  error
}

func testTransactionalReload(v *verifier) error {
	directory := filepath.Join(v.root, "transactional reload")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	cfg := baseConfig()
	cfg.WorkerCount = 1
	cfg.RetryBaseMS = 1000
	cfg.MaxAttempts = 2
	configPath, cfg, err := v.prepareConfig(directory, cfg)
	if err != nil {
		return err
	}
	svc, err := startService(v.binDir, configPath, cfg.Listen, filepath.Join(directory, "logs"))
	if err != nil {
		return err
	}
	defer svc.kill()

	rejected := cfg
	rejected.SyncWAL = !cfg.SyncWAL
	if err := writeJSON(configPath, rejected); err != nil {
		return err
	}
	status, raw, err := svc.requestJSON(http.MethodPost, "/v1/admin/reload", nil)
	if err != nil || status != http.StatusConflict {
		return fmt.Errorf("restart-required reload status=%d err=%v body=%s", status, err, strings.TrimSpace(string(raw)))
	}
	before, err := svc.readStats()
	if err != nil {
		return err
	}
	if before.Config.Generation != 1 || before.Config.SyncWAL != cfg.SyncWAL || before.Runtime.ActiveWorkerLimit != 1 {
		return fmt.Errorf("rejected reload changed state: %+v", before)
	}

	firstPayload := v.bytes(32771)
	secondPayload := v.bytes(24593)
	firstFixture, firstFIFO, err := v.makeFIFOFixture(directory, "fifo first", firstPayload)
	if err != nil {
		return err
	}
	secondFixture, secondFIFO, err := v.makeFIFOFixture(directory, "fifo second", secondPayload)
	if err != nil {
		return err
	}
	firstStatus, firstSubmit, raw, err := svc.submit(jobSpec{
		RequestID: v.token("fifo-one"), Manifest: firstFixture.Manifest,
		Destination: filepath.Join(directory, "fifo archive", "one.bin"), MaxAttempts: 1,
	})
	if err != nil || firstStatus != http.StatusAccepted {
		return fmt.Errorf("first fifo submit status=%d err=%v body=%s", firstStatus, err, strings.TrimSpace(string(raw)))
	}
	secondStatus, secondSubmit, raw, err := svc.submit(jobSpec{
		RequestID: v.token("fifo-two"), Manifest: secondFixture.Manifest,
		Destination: filepath.Join(directory, "fifo archive", "two.bin"), MaxAttempts: 1,
	})
	if err != nil || secondStatus != http.StatusAccepted {
		return fmt.Errorf("second fifo submit status=%d err=%v body=%s", secondStatus, err, strings.TrimSpace(string(raw)))
	}

	openResults := make(chan fifoOpenResult, 2)
	for _, path := range []string{firstFIFO, secondFIFO} {
		go func(path string) {
			file, openErr := os.OpenFile(path, os.O_WRONLY, 0)
			openResults <- fifoOpenResult{path: path, file: file, err: openErr}
		}(path)
	}
	var opened []fifoOpenResult
	select {
	case result := <-openResults:
		if result.err != nil {
			return result.err
		}
		opened = append(opened, result)
	case <-time.After(2 * time.Second):
		return fmt.Errorf("initial worker did not open either FIFO")
	}
	select {
	case result := <-openResults:
		if result.file != nil {
			_ = result.file.Close()
		}
		return fmt.Errorf("worker limit 1 admitted a second blocked publish before reload: path=%s err=%v", result.path, result.err)
	case <-time.After(150 * time.Millisecond):
	}

	updated := cfg
	updated.WorkerCount = 2
	updated.RetryBaseMS = 250
	updated.MaxAttempts = 4
	updated.MaxRequestBytes = 4096
	if err := writeJSON(configPath, updated); err != nil {
		return err
	}
	status, raw, err = svc.requestJSON(http.MethodPost, "/v1/admin/reload", nil)
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("mutable reload status=%d err=%v body=%s", status, err, strings.TrimSpace(string(raw)))
	}
	select {
	case result := <-openResults:
		if result.err != nil {
			return result.err
		}
		opened = append(opened, result)
	case <-time.After(2 * time.Second):
		return fmt.Errorf("successful worker_count reload did not admit second blocked publish")
	}
	after, err := svc.readStats()
	if err != nil {
		return err
	}
	if after.Config.Generation != 2 || after.Config.WorkerCount != 2 || after.Config.RetryBaseMS != 250 ||
		after.Config.MaxAttempts != 4 || after.Config.MaxRequestBytes != 4096 || after.Runtime.ActiveWorkerLimit != 2 {
		return fmt.Errorf("mutable reload not coherent: %+v", after)
	}
	payloads := map[string][]byte{firstFIFO: firstPayload, secondFIFO: secondPayload}
	for _, result := range opened {
		if _, err := result.file.Write(payloads[result.path]); err != nil {
			_ = result.file.Close()
			return err
		}
		if err := result.file.Close(); err != nil {
			return err
		}
	}
	for _, id := range []string{firstSubmit.Job.ID, secondSubmit.Job.ID} {
		value, err := waitTerminal(svc, id, 5*time.Second)
		if err != nil {
			return err
		}
		if value.Status != "succeeded" {
			return fmt.Errorf("FIFO job failed after reload: %+v", value)
		}
	}

	retryData := v.bytes(7777)
	retryFixture, err := v.makeFixture(directory, "retry fixture", [][]byte{retryData})
	if err != nil {
		return err
	}
	if err := os.Remove(retryFixture.ChunkPaths[0]); err != nil {
		return err
	}
	status, retrySubmit, raw, err := svc.submit(jobSpec{
		RequestID: v.token("reload-retry"), Manifest: retryFixture.Manifest,
		Destination: filepath.Join(directory, "retry archive", "retry.bin"),
	})
	if err != nil || status != http.StatusAccepted {
		return fmt.Errorf("retry submit status=%d err=%v body=%s", status, err, strings.TrimSpace(string(raw)))
	}
	retrying, err := waitForJob(svc, retrySubmit.Job.ID, 1*time.Second, func(value job) bool {
		return value.Status == "retry_wait" && value.Attempts >= 1
	})
	if err != nil {
		return err
	}
	if retrying.Spec.MaxAttempts != 4 {
		return fmt.Errorf("new default max_attempts not applied: %+v", retrying.Spec)
	}
	if err := os.WriteFile(retryFixture.ChunkPaths[0], retryData, 0o600); err != nil {
		return err
	}
	retryStarted := time.Now()
	retried, err := waitTerminal(svc, retrySubmit.Job.ID, 850*time.Millisecond)
	if err != nil {
		return fmt.Errorf("new retry_base_ms was not live within 850ms: %w", err)
	}
	if retried.Status != "succeeded" || time.Since(retryStarted) >= 850*time.Millisecond {
		return fmt.Errorf("retried job mismatch: %+v elapsed=%s", retried, time.Since(retryStarted))
	}

	oversized := []byte(`{"request_id":"oversized","manifest":"m","destination":"d","padding":"` + strings.Repeat("x", 5000) + `"}`)
	status, raw, err = svc.requestRaw(http.MethodPost, "/v1/jobs", "application/json", oversized)
	if err != nil || status != http.StatusBadRequest {
		return fmt.Errorf("reloaded max_request_bytes not enforced: status=%d err=%v body=%s", status, err, strings.TrimSpace(string(raw)))
	}
	if err := svc.stop(); err != nil {
		return err
	}
	return nil
}

func testConcurrentWALCompaction(v *verifier) error {
	directory := filepath.Join(v.root, "concurrent wal compact")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	cfg := baseConfig()
	cfg.WorkerCount = 8
	cfg.SyncWAL = false
	cfg.QueueCapacity = 4096
	configPath, cfg, err := v.prepareConfig(directory, cfg)
	if err != nil {
		return err
	}
	svc, err := startService(v.binDir, configPath, cfg.Listen, filepath.Join(directory, "logs-one"))
	if err != nil {
		return err
	}
	defer svc.kill()
	generated, err := v.makeFixture(directory, "shared fixture", [][]byte{v.bytes(2053), v.bytes(3079)})
	if err != nil {
		return err
	}

	const count = 120
	type submitOutcome struct {
		requestID string
		jobID     string
		status    int
		raw       []byte
		err       error
	}
	outcomes := make([]submitOutcome, count)
	start := make(chan struct{})
	var submitGroup sync.WaitGroup
	for index := range outcomes {
		requestID := v.token(fmt.Sprintf("bulk-%03d", index))
		outcomes[index].requestID = requestID
		submitGroup.Add(1)
		go func(index int, requestID string) {
			defer submitGroup.Done()
			<-start
			status, result, raw, submitErr := svc.submit(jobSpec{
				RequestID: requestID, Manifest: generated.Manifest,
				Destination: filepath.Join(directory, "bulk archive", requestID+".bin"), MaxAttempts: 2,
			})
			outcomes[index].status = status
			outcomes[index].raw = raw
			outcomes[index].err = submitErr
			outcomes[index].jobID = result.Job.ID
		}(index, requestID)
	}
	compactErrors := make(chan error, 1)
	go func() {
		<-start
		for index := 0; index < 35; index++ {
			status, raw, requestErr := svc.requestJSON(http.MethodPost, "/v1/admin/compact", nil)
			if requestErr != nil || status != http.StatusOK {
				compactErrors <- fmt.Errorf("compact %d status=%d err=%v body=%s", index, status, requestErr, strings.TrimSpace(string(raw)))
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
		compactErrors <- nil
	}()
	close(start)
	submitGroup.Wait()
	if err := <-compactErrors; err != nil {
		return err
	}
	for index, outcome := range outcomes {
		if outcome.err != nil || outcome.status != http.StatusAccepted || outcome.jobID == "" {
			return fmt.Errorf("bulk submit %d status=%d job=%q err=%v body=%s", index, outcome.status, outcome.jobID, outcome.err, strings.TrimSpace(string(outcome.raw)))
		}
	}
	for index, outcome := range outcomes {
		completed, err := waitTerminal(svc, outcome.jobID, 15*time.Second)
		if err != nil {
			return fmt.Errorf("bulk job %d: %w", index, err)
		}
		if completed.Status != "succeeded" || completed.ArtifactSHA != generated.ArtifactSHA {
			return fmt.Errorf("bulk job %d completion=%+v", index, completed)
		}
	}
	if err := svc.stop(); err != nil {
		return err
	}

	snapshotLast, err := readSnapshotLast(filepath.Join(cfg.StateDir, "snapshot.json"))
	if err != nil {
		return fmt.Errorf("independent snapshot parse: %w", err)
	}
	if snapshotLast == 0 {
		return fmt.Errorf("concurrent explicit compaction did not produce a nonempty snapshot")
	}
	scan, err := scanWAL(filepath.Join(cfg.StateDir, "events.wal"), snapshotLast)
	if err != nil {
		return fmt.Errorf("independent WAL scan after concurrent compaction: %w", err)
	}
	if scan.LastSequence < snapshotLast {
		return fmt.Errorf("WAL/snapshot sequence regressed: snapshot=%d scan=%+v", snapshotLast, scan)
	}

	address, err := reserveAddress()
	if err != nil {
		return err
	}
	cfg.Listen = address
	if err := writeJSON(configPath, cfg); err != nil {
		return err
	}
	restarted, err := startService(v.binDir, configPath, cfg.Listen, filepath.Join(directory, "logs-two"))
	if err != nil {
		return fmt.Errorf("restart after concurrent compaction: %w", err)
	}
	defer restarted.kill()
	for index, outcome := range outcomes {
		jobs, err := restarted.listByRequest(outcome.requestID)
		if err != nil || len(jobs) != 1 || jobs[0].ID != outcome.jobID || jobs[0].Status != "succeeded" {
			return fmt.Errorf("recovered bulk request %d jobs=%+v err=%v", index, jobs, err)
		}
	}
	receipts, err := readReceipts(filepath.Join(cfg.StateDir, "receipts.jsonl"))
	if err != nil {
		return err
	}
	seen := make(map[string]int)
	for _, value := range receipts {
		seen[value.RequestID]++
	}
	for index, outcome := range outcomes {
		if seen[outcome.requestID] != 1 {
			return fmt.Errorf("bulk request %d receipt count=%d", index, seen[outcome.requestID])
		}
	}
	if err := restarted.stop(); err != nil {
		return err
	}
	return nil
}

func testCorruptionFailsClosed(v *verifier) error {
	directory := filepath.Join(v.root, "corrupt state")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	cfg := baseConfig()
	cfg.WorkerCount = 1
	cfg.SyncWAL = true
	configPath, cfg, err := v.prepareConfig(directory, cfg)
	if err != nil {
		return err
	}
	svc, err := startService(v.binDir, configPath, cfg.Listen, filepath.Join(directory, "logs-source"))
	if err != nil {
		return err
	}
	defer svc.kill()
	generated, err := v.makeFixture(directory, "corruption fixture", [][]byte{v.bytes(4093), v.bytes(6151)})
	if err != nil {
		return err
	}
	status, submitted, raw, err := svc.submit(jobSpec{
		RequestID: v.token("corruption-source"), Manifest: generated.Manifest,
		Destination: filepath.Join(directory, "archive", "source.bin"), MaxAttempts: 1,
	})
	if err != nil || status != http.StatusAccepted {
		return fmt.Errorf("corruption source submit status=%d err=%v body=%s", status, err, strings.TrimSpace(string(raw)))
	}
	completed, err := waitTerminal(svc, submitted.Job.ID, 5*time.Second)
	if err != nil || completed.Status != "succeeded" {
		return fmt.Errorf("corruption source completion=%+v err=%v", completed, err)
	}
	if err := svc.stop(); err != nil {
		return err
	}
	sourceWAL := filepath.Join(cfg.StateDir, "events.wal")
	_, original, err := fileDigest(sourceWAL)
	if err != nil {
		return err
	}
	if len(original) < 32 {
		return fmt.Errorf("source WAL unexpectedly short: %d", len(original))
	}

	cases := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"truncated-payload", func(raw []byte) []byte { return append([]byte(nil), raw[:len(raw)-7]...) }},
		{"checksum-damage", func(raw []byte) []byte {
			copyOfRaw := append([]byte(nil), raw...)
			copyOfRaw[len(copyOfRaw)-1] ^= 0x40
			return copyOfRaw
		}},
	}
	for _, item := range cases {
		caseDir := filepath.Join(directory, item.name)
		stateDir := filepath.Join(caseDir, "state")
		if err := copyTree(cfg.StateDir, stateDir); err != nil {
			return err
		}
		walPath := filepath.Join(stateDir, "events.wal")
		mutated := item.mutate(original)
		if err := os.WriteFile(walPath, mutated, 0o600); err != nil {
			return err
		}
		beforeDigest, _, err := fileDigest(walPath)
		if err != nil {
			return err
		}
		caseConfig := cfg
		caseConfig.StateDir = stateDir
		caseConfig.Listen, err = reserveAddress()
		if err != nil {
			return err
		}
		caseConfigPath := filepath.Join(caseDir, "relay.json")
		if err := writeJSON(caseConfigPath, caseConfig); err != nil {
			return err
		}
		output, err := expectStartupFailure(v.binDir, caseConfigPath, 1200*time.Millisecond)
		if err != nil {
			return fmt.Errorf("%s did not fail closed: %w output=%s", item.name, err, strings.TrimSpace(output))
		}
		afterDigest, afterRaw, err := fileDigest(walPath)
		if err != nil {
			return err
		}
		if afterDigest != beforeDigest || !bytes.Equal(afterRaw, mutated) {
			return fmt.Errorf("%s startup rewrote damaged WAL", item.name)
		}
	}
	return nil
}
