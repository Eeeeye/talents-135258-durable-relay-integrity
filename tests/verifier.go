package main

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
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
		{"strict-http-contract", testStrictHTTPContract},
		{"durable-idempotency", testDurableIdempotency},
		{"queue-admission-ownership", testQueueAdmissionOwnership},
		{"success-receipt-crash-recovery", testSuccessReceiptCrashRecovery},
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

func testStrictHTTPContract(v *verifier) error {
	directory := filepath.Join(v.root, "strict http")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	cfg := baseConfig()
	cfg.WorkerCount = 1
	configPath, cfg, err := v.prepareConfig(directory, cfg)
	if err != nil {
		return err
	}
	svc, err := startService(v.binDir, configPath, cfg.Listen, filepath.Join(directory, "logs"))
	if err != nil {
		return err
	}
	defer svc.kill()

	generated, err := v.makeFixture(directory, "strict fixture", [][]byte{v.bytes(97)})
	if err != nil {
		return err
	}
	destination := filepath.Join(directory, "archive", "strict.bin")
	validOne := v.token("strict-unknown")
	validTwo := v.token("strict-trailing")
	validThree := v.token("strict-multiple")
	invalidBodies := []struct {
		name       string
		body       []byte
		statusCode int
		errorCode  string
	}{
		{
			name: "small unknown field",
			body: []byte(fmt.Sprintf(`{"request_id":%q,"manifest":%q,"destination":%q,"unknown":true}`,
				validOne, generated.Manifest, destination)),
			statusCode: http.StatusBadRequest,
			errorCode:  "invalid_json",
		},
		{
			name: "trailing non JSON",
			body: []byte(fmt.Sprintf(`{"request_id":%q,"manifest":%q,"destination":%q} trailing`,
				validTwo, generated.Manifest, destination)),
			statusCode: http.StatusBadRequest,
			errorCode:  "invalid_json",
		},
		{
			name: "multiple JSON values",
			body: []byte(fmt.Sprintf(`{"request_id":%q,"manifest":%q,"destination":%q}{}`,
				validThree, generated.Manifest, destination)),
			statusCode: http.StatusBadRequest,
			errorCode:  "invalid_json",
		},
		{
			name:       "request id slash",
			body:       []byte(fmt.Sprintf(`{"request_id":"bad/id","manifest":%q,"destination":%q}`, generated.Manifest, destination)),
			statusCode: http.StatusBadRequest,
			errorCode:  "invalid_job",
		},
		{
			name:       "request id leading punctuation",
			body:       []byte(fmt.Sprintf(`{"request_id":"-bad","manifest":%q,"destination":%q}`, generated.Manifest, destination)),
			statusCode: http.StatusBadRequest,
			errorCode:  "invalid_job",
		},
		{
			name:       "request id too long",
			body:       []byte(fmt.Sprintf(`{"request_id":%q,"manifest":%q,"destination":%q}`, strings.Repeat("a", 129), generated.Manifest, destination)),
			statusCode: http.StatusBadRequest,
			errorCode:  "invalid_job",
		},
	}
	for _, item := range invalidBodies {
		before, err := svc.readStats()
		if err != nil {
			return err
		}
		status, raw, err := svc.requestRaw(http.MethodPost, "/v1/jobs", "application/json", item.body)
		if err != nil {
			return fmt.Errorf("%s request: %w", item.name, err)
		}
		if err := expectHTTPError(item.name, status, raw, item.statusCode, item.errorCode); err != nil {
			return err
		}
		after, err := svc.readStats()
		if err != nil {
			return err
		}
		if after.Runtime.Accepted != before.Runtime.Accepted || after.LastSequence != before.LastSequence {
			return fmt.Errorf("%s created a job: before=%+v after=%+v", item.name, before, after)
		}
	}

	queryCases := []struct {
		name string
		path string
	}{
		{"missing request id", "/v1/jobs"},
		{"empty request id", "/v1/jobs?request_id="},
		{"duplicate request id", "/v1/jobs?request_id=one&request_id=two"},
		{"extra query field", "/v1/jobs?request_id=one&other=two"},
		{"invalid request id", "/v1/jobs?request_id=bad%2Fid"},
	}
	for _, item := range queryCases {
		status, raw, err := svc.requestRaw(http.MethodGet, item.path, "", nil)
		if err != nil {
			return fmt.Errorf("%s query: %w", item.name, err)
		}
		if err := expectHTTPError(item.name, status, raw, http.StatusBadRequest, "invalid_query"); err != nil {
			return err
		}
	}

	methodCases := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/v1/health"},
		{http.MethodPost, "/v1/stats"},
		{http.MethodDelete, "/v1/jobs"},
		{http.MethodPost, "/v1/jobs/not-present"},
		{http.MethodGet, "/v1/admin/reload"},
		{http.MethodGet, "/v1/admin/compact"},
	}
	for _, item := range methodCases {
		label := item.method + " " + item.path
		status, raw, err := svc.requestRaw(item.method, item.path, "", nil)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if err := expectHTTPError(label, status, raw, http.StatusMethodNotAllowed, "method_not_allowed"); err != nil {
			return err
		}
	}
	for label, path := range map[string]string{
		"unknown route":  "/v1/not-present",
		"traversal path": "/v1/jobs/%2e%2e%2fsecret",
	} {
		status, raw, err := svc.requestRaw(http.MethodGet, path, "", nil)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if err := expectHTTPError(label, status, raw, http.StatusNotFound, "not_found"); err != nil {
			return err
		}
	}

	if err := svc.stop(); err != nil {
		return err
	}
	return nil
}

func expectHTTPError(label string, status int, raw []byte, expectedStatus int, expectedCode string) error {
	var envelope errorEnvelope
	decodeErr := json.Unmarshal(raw, &envelope)
	if status != expectedStatus || decodeErr != nil || envelope.Error.Code != expectedCode || envelope.Error.Message == "" {
		return fmt.Errorf("%s status=%d code=%q decode=%v body=%s", label, status, envelope.Error.Code, decodeErr, strings.TrimSpace(string(raw)))
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

	manifestLexicalDir := filepath.Join(generated.Dir, "lexical segment")
	destinationDir := filepath.Dir(spec.Destination)
	destinationLexicalDir := filepath.Join(destinationDir, "lexical segment")
	if err := os.MkdirAll(manifestLexicalDir, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(destinationLexicalDir, 0o700); err != nil {
		return err
	}
	destinationLink := filepath.Join(directory, "archive symlink")
	if err := os.Symlink(destinationDir, destinationLink); err != nil {
		return err
	}

	type idempotencyCheck struct {
		name         string
		spec         jobSpec
		wantExisting bool
	}
	unchanged := spec
	unicodeWhitespace := spec
	unicodeWhitespace.Manifest = "\u2003\u00a0" + spec.Manifest + "\u3000"
	unicodeWhitespace.Destination = "\u2002" + spec.Destination + "\u205f\t"
	explicitDefault := spec
	explicitDefault.MaxAttempts = cfg.MaxAttempts
	separator := string(os.PathSeparator)
	manifestDotDot := spec
	manifestDotDot.Manifest = manifestLexicalDir + separator + ".." + separator + filepath.Base(generated.Manifest)
	destinationDotDot := spec
	destinationDotDot.Destination = destinationLexicalDir + separator + ".." + separator + filepath.Base(spec.Destination)
	destinationSymlink := spec
	destinationSymlink.Destination = filepath.Join(destinationLink, filepath.Base(spec.Destination))
	differentAttempts := spec
	differentAttempts.MaxAttempts = cfg.MaxAttempts + 1
	differentDestination := spec
	differentDestination.Destination = filepath.Join(destinationDir, "conflicting.bin")
	checks := []idempotencyCheck{
		{name: "unchanged", spec: unchanged, wantExisting: true},
		{name: "Unicode whitespace", spec: unicodeWhitespace, wantExisting: true},
		{name: "explicit effective default", spec: explicitDefault, wantExisting: true},
		{name: "manifest dot-dot alias", spec: manifestDotDot},
		{name: "destination dot-dot alias", spec: destinationDotDot},
		{name: "destination symlink alias", spec: destinationSymlink},
		{name: "different effective attempts", spec: differentAttempts},
		{name: "different destination", spec: differentDestination},
	}
	checkMatrix := func(stage string, target *service) error {
		for _, check := range checks {
			status, result, raw, submitErr := target.submit(check.spec)
			if submitErr != nil {
				return fmt.Errorf("%s %s submit: %w", stage, check.name, submitErr)
			}
			if check.wantExisting {
				if status != http.StatusOK || !result.Existing || result.Job.ID != jobID {
					return fmt.Errorf("%s %s duplicate status=%d result=%+v body=%s", stage, check.name, status, result, strings.TrimSpace(string(raw)))
				}
			} else {
				var envelope errorEnvelope
				_ = json.Unmarshal(raw, &envelope)
				if status != http.StatusConflict || envelope.Error.Code != "idempotency_conflict" {
					return fmt.Errorf("%s %s conflict status=%d code=%q body=%s", stage, check.name, status, envelope.Error.Code, strings.TrimSpace(string(raw)))
				}
			}
			jobs, listErr := target.listByRequest(spec.RequestID)
			if listErr != nil || len(jobs) != 1 || jobs[0].ID != jobID {
				return fmt.Errorf("%s %s changed original job: jobs=%+v err=%v", stage, check.name, jobs, listErr)
			}
		}
		return nil
	}
	if err := checkMatrix("before compact", svc); err != nil {
		return err
	}

	status, raw, err := svc.requestJSON(http.MethodPost, "/v1/admin/compact", nil)
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("compact before restart status=%d err=%v body=%s", status, err, strings.TrimSpace(string(raw)))
	}
	if err := checkMatrix("after compact", svc); err != nil {
		return err
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
	if err := checkMatrix("after restart", restarted); err != nil {
		return err
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

func testQueueAdmissionOwnership(v *verifier) error {
	directory := filepath.Join(v.root, "queue admission ownership")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	cfg := baseConfig()
	cfg.WorkerCount = 1
	cfg.QueueCapacity = 1
	cfg.MaxAttempts = 1
	configPath, cfg, err := v.prepareConfig(directory, cfg)
	if err != nil {
		return err
	}
	svc, err := startService(v.binDir, configPath, cfg.Listen, filepath.Join(directory, "logs-one"))
	if err != nil {
		return err
	}
	defer svc.kill()

	blockingPayload := v.bytes(4099)
	blocking, fifoPath, err := v.makeFIFOFixture(directory, "blocking fixture", blockingPayload)
	if err != nil {
		return err
	}
	status, blocked, raw, err := svc.submit(jobSpec{
		RequestID: v.token("queue-blocker"), Manifest: blocking.Manifest,
		Destination: filepath.Join(directory, "archive", "blocker.bin"), MaxAttempts: 1,
	})
	if err != nil || status != http.StatusAccepted {
		return fmt.Errorf("queue blocker status=%d err=%v body=%s", status, err, strings.TrimSpace(string(raw)))
	}

	writerResults := make(chan fifoOpenResult, 1)
	go func() {
		file, openErr := os.OpenFile(fifoPath, os.O_WRONLY, 0)
		writerResults <- fifoOpenResult{path: fifoPath, file: file, err: openErr}
	}()
	var blockingWriter *os.File
	select {
	case result := <-writerResults:
		if result.err != nil {
			return result.err
		}
		blockingWriter = result.file
	case <-time.After(2 * time.Second):
		return errors.New("queue blocker did not enter its FIFO publish")
	}
	defer func() {
		if blockingWriter != nil {
			_ = blockingWriter.Close()
		}
	}()

	ordinary, err := v.makeFixture(directory, "queued fixture", [][]byte{v.bytes(257)})
	if err != nil {
		return err
	}
	acceptedIDs := make([]string, 0, 64)
	rejected := make([]jobSpec, 0, 2)
	for index := 0; index < 256 && len(rejected) < 2; index++ {
		candidate := jobSpec{
			RequestID:   v.token(fmt.Sprintf("queue-candidate-%03d", index)),
			Manifest:    ordinary.Manifest,
			Destination: filepath.Join(directory, "queued archive", fmt.Sprintf("candidate-%03d.bin", index)),
			MaxAttempts: 1,
		}
		candidateStatus, result, candidateRaw, submitErr := svc.submit(candidate)
		if submitErr != nil {
			return submitErr
		}
		switch candidateStatus {
		case http.StatusAccepted:
			if result.Existing || result.Job.ID == "" {
				return fmt.Errorf("fresh queued submission returned %+v", result)
			}
			acceptedIDs = append(acceptedIDs, result.Job.ID)
		case http.StatusServiceUnavailable:
			var envelope errorEnvelope
			_ = json.Unmarshal(candidateRaw, &envelope)
			if envelope.Error.Code != "queue_full" {
				return fmt.Errorf("queue rejection code=%q body=%s", envelope.Error.Code, strings.TrimSpace(string(candidateRaw)))
			}
			rejected = append(rejected, candidate)
		default:
			return fmt.Errorf("queue saturation status=%d result=%+v body=%s", candidateStatus, result, strings.TrimSpace(string(candidateRaw)))
		}
	}
	if len(rejected) != 2 {
		return fmt.Errorf("bounded queue did not reject two submissions; accepted=%d rejected=%d", len(acceptedIDs), len(rejected))
	}
	for _, candidate := range rejected {
		jobs, listErr := svc.listByRequest(candidate.RequestID)
		if listErr != nil || len(jobs) != 0 {
			return fmt.Errorf("queue_full request %q already owns durable state: jobs=%+v err=%v", candidate.RequestID, jobs, listErr)
		}
	}
	status, raw, err = svc.requestJSON(http.MethodPost, "/v1/admin/compact", nil)
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("compact with rejected admissions status=%d err=%v body=%s", status, err, strings.TrimSpace(string(raw)))
	}
	for _, candidate := range rejected {
		jobs, listErr := svc.listByRequest(candidate.RequestID)
		if listErr != nil || len(jobs) != 0 {
			return fmt.Errorf("compact materialized queue_full request %q: jobs=%+v err=%v", candidate.RequestID, jobs, listErr)
		}
	}

	if _, err := blockingWriter.Write(blockingPayload); err != nil {
		return err
	}
	if err := blockingWriter.Close(); err != nil {
		return err
	}
	blockingWriter = nil
	blockedJob, err := waitTerminal(svc, blocked.Job.ID, 12*time.Second)
	if err != nil || blockedJob.Status != "succeeded" {
		return fmt.Errorf("queue blocker completion=%+v err=%v", blockedJob, err)
	}
	for _, id := range acceptedIDs {
		completed, waitErr := waitTerminal(svc, id, 12*time.Second)
		if waitErr != nil || completed.Status != "succeeded" {
			return fmt.Errorf("admitted queued job %q completion=%+v err=%v", id, completed, waitErr)
		}
	}

	status, immediate, raw, err := svc.submit(rejected[0])
	if err != nil || status != http.StatusAccepted || immediate.Existing || immediate.Job.ID == "" {
		return fmt.Errorf("queue_full retry did not become first acceptance: status=%d result=%+v err=%v body=%s", status, immediate, err, strings.TrimSpace(string(raw)))
	}
	immediateJob, err := waitTerminal(svc, immediate.Job.ID, 8*time.Second)
	if err != nil || immediateJob.Status != "succeeded" {
		return fmt.Errorf("queue_full retry completion=%+v err=%v", immediateJob, err)
	}
	remaining, err := svc.listByRequest(rejected[1].RequestID)
	if err != nil || len(remaining) != 0 {
		return fmt.Errorf("untouched queue_full request became visible: jobs=%+v err=%v", remaining, err)
	}
	status, raw, err = svc.requestJSON(http.MethodPost, "/v1/admin/compact", nil)
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("compact before queue restart status=%d err=%v body=%s", status, err, strings.TrimSpace(string(raw)))
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
	remaining, err = restarted.listByRequest(rejected[1].RequestID)
	if err != nil || len(remaining) != 0 {
		return fmt.Errorf("queue_full request survived restart: jobs=%+v err=%v", remaining, err)
	}
	status, afterRestart, raw, err := restarted.submit(rejected[1])
	if err != nil || status != http.StatusAccepted || afterRestart.Existing || afterRestart.Job.ID == "" {
		return fmt.Errorf("post-restart queue_full retry status=%d result=%+v err=%v body=%s", status, afterRestart, err, strings.TrimSpace(string(raw)))
	}
	afterRestartJob, err := waitTerminal(restarted, afterRestart.Job.ID, 8*time.Second)
	if err != nil || afterRestartJob.Status != "succeeded" {
		return fmt.Errorf("post-restart queue retry completion=%+v err=%v", afterRestartJob, err)
	}
	if err := restarted.stop(); err != nil {
		return err
	}
	return nil
}

func testSuccessReceiptCrashRecovery(v *verifier) error {
	directory := filepath.Join(v.root, "success receipt crash")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	cfg := baseConfig()
	cfg.WorkerCount = 1
	cfg.MaxAttempts = 2
	cfg.SyncWAL = true
	configPath, cfg, err := v.prepareConfig(directory, cfg)
	if err != nil {
		return err
	}
	svc, err := startService(v.binDir, configPath, cfg.Listen, filepath.Join(directory, "logs-one"))
	if err != nil {
		return err
	}
	defer svc.kill()

	payload := v.bytes(1)
	generated, fifoPath, err := v.makeFIFOFixture(directory, "crash fixture", payload)
	if err != nil {
		return err
	}
	spec := jobSpec{
		RequestID: v.token("receipt-crash"), Manifest: generated.Manifest,
		Destination: filepath.Join(directory, "archive", "crash-safe.bin"), MaxAttempts: 2,
	}
	status, submitted, raw, err := svc.submit(spec)
	if err != nil || status != http.StatusAccepted || submitted.Job.ID == "" {
		return fmt.Errorf("crash-window submit status=%d result=%+v err=%v body=%s", status, submitted, err, strings.TrimSpace(string(raw)))
	}
	writerResult := make(chan fifoOpenResult, 1)
	go func() {
		file, openErr := os.OpenFile(fifoPath, os.O_WRONLY, 0)
		writerResult <- fifoOpenResult{path: fifoPath, file: file, err: openErr}
	}()
	var fifoWriter *os.File
	select {
	case opened := <-writerResult:
		if opened.err != nil {
			return opened.err
		}
		fifoWriter = opened.file
	case <-time.After(5 * time.Second):
		return fmt.Errorf("publisher did not enter the controlled crash fixture")
	}
	walInfo, err := os.Stat(filepath.Join(cfg.StateDir, "events.wal"))
	if err != nil {
		_ = fifoWriter.Close()
		return err
	}
	if walInfo.Size() < 1024 {
		_ = fifoWriter.Close()
		return fmt.Errorf("pre-success WAL is too small for safe failure injection: %d", walInfo.Size())
	}
	if err := setProcessFileSizeLimit(svc.cmd.Process.Pid, uint64(walInfo.Size())); err != nil {
		_ = fifoWriter.Close()
		return fmt.Errorf("limit next durable write: %w", err)
	}
	if _, err := fifoWriter.Write(payload); err != nil {
		_ = fifoWriter.Close()
		return err
	}
	if err := fifoWriter.Close(); err != nil {
		return err
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		observed, readErr := os.ReadFile(spec.Destination)
		if readErr == nil && bytes.Equal(observed, payload) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	observed, err := os.ReadFile(spec.Destination)
	if err != nil || !bytes.Equal(observed, payload) {
		return fmt.Errorf("artifact was not published before injected termination: bytes=%d err=%v", len(observed), err)
	}
	time.Sleep(50 * time.Millisecond)
	svc.kill()

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
		return fmt.Errorf("restart after receipt-edge kill: %w", err)
	}
	defer restarted.kill()
	restartWriter := make(chan fifoOpenResult, 1)
	go func() {
		file, openErr := os.OpenFile(fifoPath, os.O_WRONLY, 0)
		restartWriter <- fifoOpenResult{path: fifoPath, file: file, err: openErr}
	}()
	select {
	case opened := <-restartWriter:
		if opened.err != nil {
			return opened.err
		}
		if _, err := opened.file.Write(payload); err != nil {
			_ = opened.file.Close()
			return err
		}
		if err := opened.file.Close(); err != nil {
			return err
		}
	case <-time.After(2 * time.Second):
		return fmt.Errorf("recovered attempt did not reopen controlled fixture")
	}
	recovered, err := waitTerminal(restarted, submitted.Job.ID, 5*time.Second)
	if err != nil {
		return err
	}
	if recovered.Status != "succeeded" || recovered.Attempts != 2 || recovered.ArtifactSHA != generated.ArtifactSHA {
		return fmt.Errorf("receipt-edge recovery changed successful job: %+v", recovered)
	}
	jobs, err := restarted.listByRequest(spec.RequestID)
	if err != nil || len(jobs) != 1 || jobs[0].ID != submitted.Job.ID {
		return fmt.Errorf("receipt-edge recovery changed identity: jobs=%+v err=%v", jobs, err)
	}
	receipts, err := readReceipts(filepath.Join(cfg.StateDir, "receipts.jsonl"))
	if err != nil {
		return err
	}
	count := 0
	for _, value := range receipts {
		if value.RequestID == spec.RequestID {
			count++
			if value.JobID != submitted.Job.ID || value.ArtifactSHA256 != generated.ArtifactSHA || !value.CompletedAt.Equal(recovered.CompletedAt) {
				return fmt.Errorf("receipt-edge receipt differs from recovered success: receipt=%+v job=%+v", value, recovered)
			}
		}
	}
	if count != 1 {
		return fmt.Errorf("receipt-edge recovery produced %d receipts", count)
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

func assertRejectedReload(svc *service, configPath, label string, candidate []byte) error {
	original, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	before, err := svc.readStats()
	if err != nil {
		return err
	}
	if err := os.WriteFile(configPath, candidate, 0o600); err != nil {
		return err
	}
	status, raw, requestErr := svc.requestJSON(http.MethodPost, "/v1/admin/reload", nil)
	restoreErr := os.WriteFile(configPath, original, 0o600)
	if restoreErr != nil {
		return fmt.Errorf("%s restore config: %w", label, restoreErr)
	}
	if requestErr != nil || status != http.StatusConflict {
		return fmt.Errorf("%s reload status=%d err=%v body=%s", label, status, requestErr, strings.TrimSpace(string(raw)))
	}
	if err := expectHTTPError(label, status, raw, http.StatusConflict, "reload_rejected"); err != nil {
		return err
	}
	after, err := svc.readStats()
	if err != nil {
		return err
	}
	if after.Config != before.Config || after.Runtime != before.Runtime || after.LastSequence != before.LastSequence {
		return fmt.Errorf("%s changed published state: before=%+v after=%+v", label, before, after)
	}
	return nil
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

	alternateListen, err := reserveAddress()
	if err != nil {
		return err
	}
	marshalConfig := func(value configFile) []byte {
		raw, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			panic(marshalErr)
		}
		return raw
	}
	validRaw := marshalConfig(cfg)
	unknownRaw := append([]byte(nil), validRaw[:len(validRaw)-1]...)
	unknownRaw = append(unknownRaw, []byte(`,"unexpected":true}`)...)
	trailingRaw := append(append([]byte(nil), validRaw...), []byte(` {}`)...)
	rejectedCases := []struct {
		name string
		cfg  configFile
		raw  []byte
	}{
		{name: "listen", cfg: cfg},
		{name: "state_dir", cfg: cfg},
		{name: "queue_capacity", cfg: cfg},
		{name: "sync_wal", cfg: cfg},
		{name: "snapshot_interval_ms", cfg: cfg},
		{name: "shutdown_timeout_ms", cfg: cfg},
		{name: "invalid live value", cfg: cfg},
		{name: "malformed JSON", raw: []byte(`{"listen":`)},
		{name: "unknown field", raw: unknownRaw},
		{name: "trailing JSON", raw: trailingRaw},
	}
	rejectedCases[0].cfg.Listen = alternateListen
	rejectedCases[1].cfg.StateDir = filepath.Join(directory, "different state")
	rejectedCases[2].cfg.QueueCapacity++
	rejectedCases[3].cfg.SyncWAL = !cfg.SyncWAL
	rejectedCases[4].cfg.SnapshotIntervalMS = 50
	rejectedCases[5].cfg.ShutdownTimeoutMS++
	rejectedCases[6].cfg.WorkerCount = 0
	for _, item := range rejectedCases {
		raw := item.raw
		if raw == nil {
			raw = marshalConfig(item.cfg)
		}
		if err := assertRejectedReload(svc, configPath, item.name, raw); err != nil {
			return err
		}
	}
	before, err := svc.readStats()
	if err != nil {
		return err
	}
	if before.Config.Generation != 1 || before.Config != (configSnapshot{Generation: 1, configFile: cfg}) || before.Runtime.ActiveWorkerLimit != 1 {
		return fmt.Errorf("rejected reload matrix changed baseline: %+v", before)
	}

	firstPayload := v.bytes(32771)
	secondPayload := v.bytes(24593)
	thirdPayload := v.bytes(19301)
	firstFixture, firstFIFO, err := v.makeFIFOFixture(directory, "fifo first", firstPayload)
	if err != nil {
		return err
	}
	thirdFixture, thirdFIFO, err := v.makeFIFOFixture(directory, "fifo third", thirdPayload)
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

	openResults := make(chan fifoOpenResult, 3)
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
	updated.RetryBaseMS = 150
	updated.MaxAttempts = 4
	updated.MaxRequestBytes = 4096
	if err := writeJSON(configPath, updated); err != nil {
		return err
	}
	status, raw, err := svc.requestJSON(http.MethodPost, "/v1/admin/reload", nil)
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
	if after.Config.Generation != 2 || after.Config.WorkerCount != 2 || after.Config.RetryBaseMS != 150 ||
		after.Config.MaxAttempts != 4 || after.Config.MaxRequestBytes != 4096 || after.Runtime.ActiveWorkerLimit != 2 {
		return fmt.Errorf("mutable reload not coherent: %+v", after)
	}

	scaledDown := updated
	scaledDown.WorkerCount = 1
	if err := writeJSON(configPath, scaledDown); err != nil {
		return err
	}
	status, raw, err = svc.requestJSON(http.MethodPost, "/v1/admin/reload", nil)
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("scale-down reload status=%d err=%v body=%s", status, err, strings.TrimSpace(string(raw)))
	}
	downStats, err := svc.readStats()
	if err != nil {
		return err
	}
	if downStats.Config.Generation != 3 || downStats.Config.WorkerCount != 1 || downStats.Runtime.ActiveWorkerLimit != 1 || downStats.Runtime.ActiveWorkers != 2 {
		return fmt.Errorf("scale-down state is not immediate and non-cancelling: %+v", downStats)
	}
	thirdStatus, thirdSubmit, raw, err := svc.submit(jobSpec{
		RequestID: v.token("fifo-three"), Manifest: thirdFixture.Manifest,
		Destination: filepath.Join(directory, "fifo archive", "three.bin"), MaxAttempts: 1,
	})
	if err != nil || thirdStatus != http.StatusAccepted {
		return fmt.Errorf("third fifo submit status=%d err=%v body=%s", thirdStatus, err, strings.TrimSpace(string(raw)))
	}
	go func() {
		file, openErr := os.OpenFile(thirdFIFO, os.O_WRONLY, 0)
		openResults <- fifoOpenResult{path: thirdFIFO, file: file, err: openErr}
	}()
	select {
	case result := <-openResults:
		if result.file != nil {
			_ = result.file.Close()
		}
		return fmt.Errorf("scale-down admitted replacement while two publishers remained active: path=%s err=%v", result.path, result.err)
	case <-time.After(150 * time.Millisecond):
	}

	payloads := map[string][]byte{firstFIFO: firstPayload, secondFIFO: secondPayload, thirdFIFO: thirdPayload}
	jobIDs := map[string]string{firstFIFO: firstSubmit.Job.ID, secondFIFO: secondSubmit.Job.ID, thirdFIFO: thirdSubmit.Job.ID}
	release := func(result fifoOpenResult) error {
		if _, err := result.file.Write(payloads[result.path]); err != nil {
			_ = result.file.Close()
			return err
		}
		return result.file.Close()
	}
	if err := release(opened[0]); err != nil {
		return err
	}
	firstCompleted, err := waitTerminal(svc, jobIDs[opened[0].path], 5*time.Second)
	if err != nil || firstCompleted.Status != "succeeded" {
		return fmt.Errorf("first released in-flight job was cancelled: job=%+v err=%v", firstCompleted, err)
	}
	select {
	case result := <-openResults:
		if result.file != nil {
			_ = result.file.Close()
		}
		return fmt.Errorf("new work entered while active_workers equaled the reduced limit: path=%s err=%v", result.path, result.err)
	case <-time.After(200 * time.Millisecond):
	}
	if err := release(opened[1]); err != nil {
		return err
	}
	var thirdOpened fifoOpenResult
	select {
	case thirdOpened = <-openResults:
		if thirdOpened.err != nil || thirdOpened.path != thirdFIFO {
			return fmt.Errorf("unexpected third FIFO open: %+v", thirdOpened)
		}
	case <-time.After(2 * time.Second):
		return fmt.Errorf("reduced worker limit did not admit queued work after both old publishers completed")
	}
	if err := release(thirdOpened); err != nil {
		return err
	}
	for _, id := range []string{firstSubmit.Job.ID, secondSubmit.Job.ID, thirdSubmit.Job.ID} {
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
	retryStarted := time.Now()
	if err := os.WriteFile(retryFixture.ChunkPaths[0], retryData, 0o600); err != nil {
		return err
	}
	retried, err := waitTerminal(svc, retrySubmit.Job.ID, 450*time.Millisecond)
	if err != nil {
		return fmt.Errorf("new retry_base_ms was not live within 450ms: %w", err)
	}
	if retried.Status != "succeeded" || time.Since(retryStarted) >= 450*time.Millisecond {
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
	sentinelRequest := v.token("post-compact-sentinel")
	sentinelStatus, sentinelSubmit, raw, err := svc.submit(jobSpec{
		RequestID: sentinelRequest, Manifest: generated.Manifest,
		Destination: filepath.Join(directory, "bulk archive", sentinelRequest+".bin"), MaxAttempts: 2,
	})
	if err != nil || sentinelStatus != http.StatusAccepted || sentinelSubmit.Job.ID == "" {
		return fmt.Errorf("post-compact sentinel status=%d err=%v body=%s", sentinelStatus, err, strings.TrimSpace(string(raw)))
	}
	sentinelCompleted, err := waitTerminal(svc, sentinelSubmit.Job.ID, 8*time.Second)
	if err != nil || sentinelCompleted.Status != "succeeded" {
		return fmt.Errorf("post-compact sentinel completion=%+v err=%v", sentinelCompleted, err)
	}
	if err := svc.stop(); err != nil {
		return err
	}

	snapshot, exists, err := readSnapshot(filepath.Join(cfg.StateDir, "snapshot.json"))
	if err != nil {
		return fmt.Errorf("independent snapshot parse: %w", err)
	}
	if !exists || snapshot.LastSequence == 0 {
		return fmt.Errorf("concurrent explicit compaction did not produce a nonempty snapshot")
	}
	scan, err := scanWAL(filepath.Join(cfg.StateDir, "events.wal"), snapshot.LastSequence)
	if err != nil {
		return fmt.Errorf("independent WAL scan after concurrent compaction: %w", err)
	}
	if scan.LastSequence < snapshot.LastSequence {
		return fmt.Errorf("WAL/snapshot sequence regressed: snapshot=%d scan=%+v", snapshot.LastSequence, scan)
	}
	durableJobs, err := replayDurableState(snapshot, scan)
	if err != nil {
		return fmt.Errorf("semantic durable-state replay: %w", err)
	}
	if len(durableJobs) != count+1 {
		return fmt.Errorf("durable state contains %d jobs, expected %d", len(durableJobs), count+1)
	}
	for index, outcome := range outcomes {
		value, ok := durableJobs[outcome.jobID]
		if !ok || value.Spec.RequestID != outcome.requestID || value.Status != "succeeded" || value.ArtifactSHA != generated.ArtifactSHA {
			return fmt.Errorf("durable bulk job %d is not represented by real state: %+v ok=%v", index, value, ok)
		}
	}
	value, ok := durableJobs[sentinelSubmit.Job.ID]
	if !ok || value.Spec.RequestID != sentinelRequest || value.Status != "succeeded" || value.ArtifactSHA != generated.ArtifactSHA {
		return fmt.Errorf("post-compact sentinel is absent from durable state: %+v ok=%v", value, ok)
	}
	var sentinelTransitions []string
	for _, event := range scan.Events {
		if event.Job.ID == sentinelSubmit.Job.ID {
			sentinelTransitions = append(sentinelTransitions, event.Type)
		}
	}
	if strings.Join(sentinelTransitions, ",") != "job_submitted,job_started,job_succeeded" {
		return fmt.Errorf("post-compact WAL does not contain real typed transitions: %v", sentinelTransitions)
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
		durable := durableJobs[outcome.jobID]
		if err != nil || len(jobs) != 1 || jobs[0].ID != outcome.jobID || !sameDurableJob(jobs[0], durable) {
			return fmt.Errorf("recovered bulk request %d jobs=%+v err=%v", index, jobs, err)
		}
	}
	sentinelJobs, err := restarted.listByRequest(sentinelRequest)
	if err != nil || len(sentinelJobs) != 1 || !sameDurableJob(sentinelJobs[0], durableJobs[sentinelSubmit.Job.ID]) {
		return fmt.Errorf("recovered sentinel jobs=%+v err=%v", sentinelJobs, err)
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
	if seen[sentinelRequest] != 1 {
		return fmt.Errorf("sentinel receipt count=%d", seen[sentinelRequest])
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
	status, raw, err = svc.requestJSON(http.MethodPost, "/v1/admin/compact", nil)
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("corruption source compact status=%d err=%v body=%s", status, err, strings.TrimSpace(string(raw)))
	}
	secondRequest := v.token("corruption-post-snapshot")
	status, secondSubmit, raw, err := svc.submit(jobSpec{
		RequestID: secondRequest, Manifest: generated.Manifest,
		Destination: filepath.Join(directory, "archive", "post-snapshot.bin"), MaxAttempts: 1,
	})
	if err != nil || status != http.StatusAccepted {
		return fmt.Errorf("post-snapshot source submit status=%d err=%v body=%s", status, err, strings.TrimSpace(string(raw)))
	}
	secondCompleted, err := waitTerminal(svc, secondSubmit.Job.ID, 5*time.Second)
	if err != nil || secondCompleted.Status != "succeeded" {
		return fmt.Errorf("post-snapshot source completion=%+v err=%v", secondCompleted, err)
	}
	if err := svc.stop(); err != nil {
		return err
	}
	sourceWAL := filepath.Join(cfg.StateDir, "events.wal")
	originalWAL, err := os.ReadFile(sourceWAL)
	if err != nil {
		return err
	}
	sourceSnapshot := filepath.Join(cfg.StateDir, "snapshot.json")
	originalSnapshot, err := os.ReadFile(sourceSnapshot)
	if err != nil {
		return err
	}
	frames, err := parseRawWALFrames(originalWAL)
	if err != nil || len(frames) < 3 {
		return fmt.Errorf("source WAL frames=%d err=%v", len(frames), err)
	}
	baseSnapshot, exists, err := readSnapshot(sourceSnapshot)
	if err != nil || !exists || baseSnapshot.LastSequence == 0 {
		return fmt.Errorf("source snapshot invalid: exists=%v snapshot=%+v err=%v", exists, baseSnapshot, err)
	}

	rewriteEvent := func(index int, mutate func(*durableEvent)) ([]byte, error) {
		copyOfFrames := cloneRawWALFrames(frames)
		var event durableEvent
		if err := json.Unmarshal(copyOfFrames[index].Payload, &event); err != nil {
			return nil, err
		}
		mutate(&event)
		payload, err := json.Marshal(event)
		if err != nil {
			return nil, err
		}
		copyOfFrames[index].Payload = payload
		return encodeRawWALFrames(copyOfFrames), nil
	}
	rewriteSnapshot := func(mutate func(*durableSnapshot)) ([]byte, error) {
		var value durableSnapshot
		if err := json.Unmarshal(originalSnapshot, &value); err != nil {
			return nil, err
		}
		mutate(&value)
		return json.Marshal(value)
	}
	type damageCase struct {
		name   string
		mutate func([]byte, []byte) ([]byte, []byte, error)
	}
	cases := []damageCase{
		{name: "partial-header", mutate: func(walRaw, snapshotRaw []byte) ([]byte, []byte, error) {
			return append([]byte(nil), walRaw[:11]...), snapshotRaw, nil
		}},
		{name: "bad-magic", mutate: func(walRaw, snapshotRaw []byte) ([]byte, []byte, error) {
			result := append([]byte(nil), walRaw...)
			result[0] ^= 0x20
			return result, snapshotRaw, nil
		}},
		{name: "bad-version", mutate: func(walRaw, snapshotRaw []byte) ([]byte, []byte, error) {
			result := append([]byte(nil), walRaw...)
			binary.LittleEndian.PutUint16(result[4:6], 2)
			return result, snapshotRaw, nil
		}},
		{name: "bad-flags", mutate: func(walRaw, snapshotRaw []byte) ([]byte, []byte, error) {
			result := append([]byte(nil), walRaw...)
			binary.LittleEndian.PutUint16(result[6:8], 1)
			return result, snapshotRaw, nil
		}},
		{name: "zero-length", mutate: func(walRaw, snapshotRaw []byte) ([]byte, []byte, error) {
			result := append([]byte(nil), walRaw...)
			binary.LittleEndian.PutUint32(result[8:12], 0)
			return result, snapshotRaw, nil
		}},
		{name: "oversized-length", mutate: func(walRaw, snapshotRaw []byte) ([]byte, []byte, error) {
			result := append([]byte(nil), walRaw...)
			binary.LittleEndian.PutUint32(result[8:12], (4<<20)+1)
			return result, snapshotRaw, nil
		}},
		{name: "zero-sequence", mutate: func(walRaw, snapshotRaw []byte) ([]byte, []byte, error) {
			result := append([]byte(nil), walRaw...)
			binary.LittleEndian.PutUint64(result[16:24], 0)
			return result, snapshotRaw, nil
		}},
		{name: "truncated-payload", mutate: func(_ []byte, snapshotRaw []byte) ([]byte, []byte, error) {
			end := 24 + len(frames[0].Payload) - 1
			return append([]byte(nil), originalWAL[:end]...), snapshotRaw, nil
		}},
		{name: "checksum-damage", mutate: func(walRaw, snapshotRaw []byte) ([]byte, []byte, error) {
			result := append([]byte(nil), walRaw...)
			result[24+len(frames[0].Payload)/2] ^= 0x40
			return result, snapshotRaw, nil
		}},
		{name: "malformed-event-json", mutate: func(_ []byte, snapshotRaw []byte) ([]byte, []byte, error) {
			copyOfFrames := cloneRawWALFrames(frames)
			copyOfFrames[0].Payload = bytes.Repeat([]byte{'x'}, len(copyOfFrames[0].Payload))
			return encodeRawWALFrames(copyOfFrames), snapshotRaw, nil
		}},
		{name: "unknown-event-field", mutate: func(_ []byte, snapshotRaw []byte) ([]byte, []byte, error) {
			copyOfFrames := cloneRawWALFrames(frames)
			payload := copyOfFrames[0].Payload
			payload = append(append([]byte(nil), payload[:len(payload)-1]...), []byte(`,"unexpected":true}`)...)
			copyOfFrames[0].Payload = payload
			return encodeRawWALFrames(copyOfFrames), snapshotRaw, nil
		}},
		{name: "trailing-event-json", mutate: func(_ []byte, snapshotRaw []byte) ([]byte, []byte, error) {
			copyOfFrames := cloneRawWALFrames(frames)
			copyOfFrames[0].Payload = append(copyOfFrames[0].Payload, []byte(`{}`)...)
			return encodeRawWALFrames(copyOfFrames), snapshotRaw, nil
		}},
		{name: "header-payload-sequence-mismatch", mutate: func(_ []byte, snapshotRaw []byte) ([]byte, []byte, error) {
			result, err := rewriteEvent(0, func(event *durableEvent) { event.Sequence++ })
			return result, snapshotRaw, err
		}},
		{name: "snapshot-relative-gap", mutate: func(_ []byte, snapshotRaw []byte) ([]byte, []byte, error) {
			copyOfFrames := cloneRawWALFrames(frames)
			newSequence := binary.LittleEndian.Uint64(copyOfFrames[0].Header[16:24]) + 1
			binary.LittleEndian.PutUint64(copyOfFrames[0].Header[16:24], newSequence)
			var event durableEvent
			if err := json.Unmarshal(copyOfFrames[0].Payload, &event); err != nil {
				return nil, nil, err
			}
			event.Sequence = newSequence
			payload, err := json.Marshal(event)
			if err != nil {
				return nil, nil, err
			}
			copyOfFrames[0].Payload = payload
			return encodeRawWALFrames(copyOfFrames), snapshotRaw, nil
		}},
		{name: "noncontiguous-wal-sequence", mutate: func(_ []byte, snapshotRaw []byte) ([]byte, []byte, error) {
			copyOfFrames := cloneRawWALFrames(frames)
			newSequence := binary.LittleEndian.Uint64(copyOfFrames[1].Header[16:24]) + 1
			binary.LittleEndian.PutUint64(copyOfFrames[1].Header[16:24], newSequence)
			var event durableEvent
			if err := json.Unmarshal(copyOfFrames[1].Payload, &event); err != nil {
				return nil, nil, err
			}
			event.Sequence = newSequence
			payload, err := json.Marshal(event)
			if err != nil {
				return nil, nil, err
			}
			copyOfFrames[1].Payload = payload
			return encodeRawWALFrames(copyOfFrames), snapshotRaw, nil
		}},
		{name: "invalid-event-type", mutate: func(_ []byte, snapshotRaw []byte) ([]byte, []byte, error) {
			result, err := rewriteEvent(0, func(event *durableEvent) { event.Type = "job_impossible" })
			return result, snapshotRaw, err
		}},
		{name: "invalid-transition-semantics", mutate: func(_ []byte, snapshotRaw []byte) ([]byte, []byte, error) {
			result, err := rewriteEvent(0, func(event *durableEvent) {
				event.Job.Status = "succeeded"
				event.Job.CompletedAt = event.Job.UpdatedAt
			})
			return result, snapshotRaw, err
		}},
		{name: "malformed-snapshot", mutate: func(walRaw, snapshotRaw []byte) ([]byte, []byte, error) {
			return walRaw, append([]byte(nil), snapshotRaw[:len(snapshotRaw)/2]...), nil
		}},
		{name: "bad-snapshot-version", mutate: func(walRaw, _ []byte) ([]byte, []byte, error) {
			result, err := rewriteSnapshot(func(value *durableSnapshot) { value.Version = 2 })
			return walRaw, result, err
		}},
		{name: "unknown-snapshot-field", mutate: func(walRaw, snapshotRaw []byte) ([]byte, []byte, error) {
			trimmed := bytes.TrimSpace(snapshotRaw)
			result := append(append([]byte(nil), trimmed[:len(trimmed)-1]...), []byte(`,"unexpected":true}`)...)
			return walRaw, result, nil
		}},
		{name: "trailing-snapshot-json", mutate: func(walRaw, snapshotRaw []byte) ([]byte, []byte, error) {
			return walRaw, append(append([]byte(nil), snapshotRaw...), []byte(`{}`)...), nil
		}},
		{name: "snapshot-job-key-mismatch", mutate: func(walRaw, _ []byte) ([]byte, []byte, error) {
			result, err := rewriteSnapshot(func(value *durableSnapshot) {
				for id, item := range value.Jobs {
					delete(value.Jobs, id)
					value.Jobs["wrong-"+id] = item
					break
				}
			})
			return walRaw, result, err
		}},
		{name: "snapshot-sequence-gap", mutate: func(walRaw, _ []byte) ([]byte, []byte, error) {
			result, err := rewriteSnapshot(func(value *durableSnapshot) { value.LastSequence++ })
			return walRaw, result, err
		}},
		{name: "nil-snapshot-jobs", mutate: func(walRaw, _ []byte) ([]byte, []byte, error) {
			result, err := rewriteSnapshot(func(value *durableSnapshot) { value.Jobs = nil })
			return walRaw, result, err
		}},
	}
	for _, item := range cases {
		caseDir := filepath.Join(directory, item.name)
		stateDir := filepath.Join(caseDir, "state")
		if err := copyTree(cfg.StateDir, stateDir); err != nil {
			return err
		}
		walPath := filepath.Join(stateDir, "events.wal")
		snapshotPath := filepath.Join(stateDir, "snapshot.json")
		mutatedWAL, mutatedSnapshot, err := item.mutate(originalWAL, originalSnapshot)
		if err != nil {
			return fmt.Errorf("construct %s damage: %w", item.name, err)
		}
		if err := os.WriteFile(walPath, mutatedWAL, 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(snapshotPath, mutatedSnapshot, 0o600); err != nil {
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
		output, err := expectStartupFailure(v.binDir, caseConfigPath, caseConfig.Listen, 1500*time.Millisecond)
		if err != nil {
			return fmt.Errorf("%s did not fail closed: %w output=%s", item.name, err, strings.TrimSpace(output))
		}
		afterWAL, err := os.ReadFile(walPath)
		if err != nil {
			return err
		}
		afterSnapshot, err := os.ReadFile(snapshotPath)
		if err != nil {
			return err
		}
		if !bytes.Equal(afterWAL, mutatedWAL) || !bytes.Equal(afterSnapshot, mutatedSnapshot) {
			return fmt.Errorf("%s startup rewrote forensic state", item.name)
		}
	}
	return nil
}
