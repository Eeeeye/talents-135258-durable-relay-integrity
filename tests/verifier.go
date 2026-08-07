package main

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/sha256"
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
	"syscall"
	"time"
)

func main() {
	binDir := flag.String("bin-dir", "", "directory containing freshly built relay binaries")
	flag.Parse()
	if *binDir == "" {
		fmt.Fprintln(os.Stderr, "verifier: -bin-dir is required")
		os.Exit(2)
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "verifier: trusted integration verifier must run as root so candidate processes can use isolated UIDs")
		os.Exit(2)
	}
	if err := enableChildSubreaper(); err != nil {
		fmt.Fprintf(os.Stderr, "verifier: become candidate child subreaper: %v\n", err)
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
	if err := prepareVerifierRoot(root); err != nil {
		fmt.Fprintf(os.Stderr, "verifier: protect temp root: %v\n", err)
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
		{"candidate-process-containment", testCandidateProcessContainment},
		{"public-cli-compatibility", testPublicCLICompatibility},
		{"ordinary-and-atomic-publication", testOrdinaryAndAtomicPublication},
		{"strict-http-contract", testStrictHTTPContract},
		{"manifest-validation-and-containment", testManifestValidationAndContainment},
		{"durable-idempotency", testDurableIdempotency},
		{"queue-admission-ownership", testQueueAdmissionOwnership},
		{"success-receipt-crash-recovery", testSuccessReceiptCrashRecovery},
		{"transactional-live-reload", testTransactionalReload},
		{"periodic-snapshot-and-listener-policy", testPeriodicSnapshotAndListenerPolicy},
		{"concurrent-wal-compaction-restart", testConcurrentWALCompaction},
		{"compaction-crash-with-nonterminal-jobs", testCompactionCrashRecovery},
		{"corrupt-state-fails-closed", testCorruptionFailsClosed},
	}

	fmt.Printf("verifier seed=%d root=%s\n", seed, root)
	for index, test := range tests {
		setCandidateIdentity(index)
		started := time.Now()
		fmt.Printf("RUN  %s candidate_uid=%d\n", test.name, activeCandidateUID)
		testErr := test.run(v)
		cleanupErr := cleanupCandidateDescendants(activeCandidateUID)
		if testErr != nil || cleanupErr != nil {
			fmt.Printf("FAIL %s (%s): %v\n", test.name, time.Since(started).Round(time.Millisecond), errors.Join(testErr, cleanupErr))
			fmt.Printf("reproduce with DURABLE_RELAY_TEST_SEED=%d\n", seed)
			os.Exit(1)
		}
		fmt.Printf("PASS %s (%s)\n", test.name, time.Since(started).Round(time.Millisecond))
	}
	fmt.Printf("all integration checks passed; seed=%d\n", seed)
}

func testCandidateProcessContainment(v *verifier) error {
	directory := filepath.Join(v.root, "candidate process containment")
	if err := prepareTestDirectory(directory); err != nil {
		return err
	}
	marker := filepath.Join(directory, "escaped-child-marker")
	// Deliberately escape the command's process group and let the immediate
	// shell exit. As a child subreaper, the verifier must adopt and terminate
	// the detached descendant before it can write after runCLI returns.
	script := `/usr/bin/setsid /bin/sh -c 'sleep 0.25; : > "$1"' marker-writer "$1" >/dev/null 2>&1 &`
	if output, err := runCLI(2*time.Second, "/bin/sh", "-c", script, "launcher", marker); err != nil {
		return fmt.Errorf("launch detached containment probe: %w: %s", err, strings.TrimSpace(string(output)))
	}
	time.Sleep(350 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		return errors.New("detached candidate descendant survived process-group and subreaper cleanup")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func testPublicCLICompatibility(v *verifier) error {
	directory := filepath.Join(v.root, "public CLI compatibility")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	cfg := baseConfig()
	configPath, cfg, err := v.prepareConfig(directory, cfg)
	if err != nil {
		return err
	}
	svc, err := startService(v.binDir, configPath, &cfg, filepath.Join(directory, "logs"))
	if err != nil {
		return err
	}
	defer svc.kill()

	fixtureRoot := filepath.Join(directory, "generated fixture with spaces")
	fixtureOutput, err := runCLI(8*time.Second, filepath.Join(v.binDir, "relayfixture"),
		"-root", fixtureRoot,
		"-mode", "valid",
		"-chunks", "3",
		"-chunk-size", strconv.Itoa(v.intBetween(1025, 4097)),
		"-seed", v.token("cli-fixture"),
	)
	if err != nil {
		return err
	}
	var generated struct {
		Manifest       string `json:"manifest"`
		ArtifactSize   int64  `json:"artifact_size"`
		ArtifactSHA256 string `json:"artifact_sha256"`
	}
	if err := json.Unmarshal(fixtureOutput, &generated); err != nil {
		return fmt.Errorf("relayfixture output: %w: %s", err, strings.TrimSpace(string(fixtureOutput)))
	}
	if generated.Manifest == "" || generated.ArtifactSize <= 0 || len(generated.ArtifactSHA256) != 64 {
		return fmt.Errorf("relayfixture summary is incomplete: %+v", generated)
	}

	ctl := func(arguments ...string) ([]byte, error) {
		global := []string{"-addr", "http://" + svc.addr, "-timeout", "8s", "-pretty"}
		return runCLI(10*time.Second, filepath.Join(v.binDir, "relayctl"), append(global, arguments...)...)
	}
	healthOutput, err := ctl("health")
	if err != nil {
		return err
	}
	var observedHealth health
	if err := json.Unmarshal(healthOutput, &observedHealth); err != nil || !observedHealth.Ready {
		return fmt.Errorf("relayctl health output=%s err=%v", strings.TrimSpace(string(healthOutput)), err)
	}

	requestID := v.token("cli-submit")
	destination := filepath.Join(directory, "CLI archive", "artifact with spaces.bin")
	submitOutput, err := ctl("submit",
		"-request", requestID,
		"-manifest", generated.Manifest,
		"-destination", destination,
		"-max-attempts", "2",
	)
	if err != nil {
		return err
	}
	var submitted submitResult
	if err := json.Unmarshal(submitOutput, &submitted); err != nil || submitted.Job.ID == "" || submitted.Existing {
		return fmt.Errorf("relayctl submit output=%s err=%v", strings.TrimSpace(string(submitOutput)), err)
	}
	waitOutput, err := ctl("wait", "-request", requestID, "-poll", "5ms")
	if err != nil {
		return err
	}
	var completed job
	if err := json.Unmarshal(waitOutput, &completed); err != nil || completed.Status != "succeeded" || completed.ID != submitted.Job.ID {
		return fmt.Errorf("relayctl wait output=%s err=%v", strings.TrimSpace(string(waitOutput)), err)
	}
	completedJobs := []job{completed}
	for _, invocation := range [][]string{
		{"get", "-id", submitted.Job.ID},
		{"list", "-request", requestID},
		{"stats"},
		{"reload"},
	} {
		if _, err := ctl(invocation...); err != nil {
			return err
		}
	}

	if _, err := runCLI(5*time.Second, filepath.Join(v.binDir, "relayinspect"),
		"artifact", "-path", destination,
		"-sha256", generated.ArtifactSHA256,
		"-size", strconv.FormatInt(generated.ArtifactSize, 10),
	); err != nil {
		return err
	}
	if _, err := runCLI(5*time.Second, filepath.Join(v.binDir, "relayinspect"),
		"wal", "-path", filepath.Join(cfg.StateDir, "events.wal"),
	); err != nil {
		return err
	}
	receiptOutput, err := runCLI(5*time.Second, filepath.Join(v.binDir, "relayinspect"),
		"receipts", "-path", filepath.Join(cfg.StateDir, "receipts.jsonl"),
		"-request", requestID, "-count-only",
	)
	if err != nil || strings.TrimSpace(string(receiptOutput)) != "1" {
		return fmt.Errorf("relayinspect receipts output=%q err=%v", strings.TrimSpace(string(receiptOutput)), err)
	}

	floodOutput, err := ctl("flood",
		"-manifest", generated.Manifest,
		"-destination-dir", filepath.Join(directory, "flood archive"),
		"-prefix", v.token("cli-flood"),
		"-count", "2",
		"-parallel", "2",
	)
	if err != nil {
		return err
	}
	var flood struct {
		Requested int      `json:"requested"`
		Accepted  int64    `json:"accepted"`
		Failed    int64    `json:"failed"`
		JobIDs    []string `json:"job_ids"`
	}
	if err := json.Unmarshal(floodOutput, &flood); err != nil || flood.Requested != 2 || flood.Accepted != 2 || flood.Failed != 0 || len(flood.JobIDs) != 2 {
		return fmt.Errorf("relayctl flood output=%s err=%v", strings.TrimSpace(string(floodOutput)), err)
	}
	for _, id := range flood.JobIDs {
		value, err := waitTerminal(svc, id, 8*time.Second)
		if err != nil || value.Status != "succeeded" {
			return fmt.Errorf("relayctl flood job %q completion=%+v err=%v", id, value, err)
		}
		completedJobs = append(completedJobs, value)
	}
	if _, err := ctl("compact"); err != nil {
		return err
	}
	snapshotOutput, err := runCLI(5*time.Second, filepath.Join(v.binDir, "relayinspect"),
		"snapshot", "-path", filepath.Join(cfg.StateDir, "snapshot.json"),
	)
	if err != nil {
		return err
	}
	var snapshotSummary struct {
		Exists       bool   `json:"exists"`
		LastSequence uint64 `json:"last_sequence"`
		Jobs         int    `json:"jobs"`
	}
	if err := json.Unmarshal(snapshotOutput, &snapshotSummary); err != nil || !snapshotSummary.Exists || snapshotSummary.LastSequence == 0 || snapshotSummary.Jobs != 3 {
		return fmt.Errorf("relayinspect snapshot output=%s err=%v", strings.TrimSpace(string(snapshotOutput)), err)
	}
	if err := assertExactReceipts(filepath.Join(cfg.StateDir, "receipts.jsonl"), completedJobs); err != nil {
		return fmt.Errorf("CLI completion receipts: %w", err)
	}
	if err := svc.stop(); err != nil {
		return err
	}
	return nil
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
	svc, err := startService(v.binDir, configPath, &cfg, filepath.Join(directory, "logs"))
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
	if err := prepareCandidateWritableDirectory(existingDir); err != nil {
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
	if err := writeCandidateReadableFile(corrupt.ChunkPaths[1], corruptBytes); err != nil {
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
	if err := assertExactReceipts(filepath.Join(cfg.StateDir, "receipts.jsonl"), []job{completed, zeroJob}); err != nil {
		return fmt.Errorf("ordinary completion receipts: %w", err)
	}

	// Hold two valid publications inside their final chunk reads, then request a
	// graceful shutdown. Once the listener closes, Engine.Close has no HTTP work
	// left to drain and cancels the publishers. Releasing the FIFO data after that
	// point distinguishes a real pre-commit cancellation check from an
	// implementation that blindly finishes and replaces the destination.
	type cancellationCase struct {
		label          string
		fixture        fixture
		fifo           string
		destination    string
		sentinel       []byte
		hadDestination bool
		jobID          string
	}
	cancellationCases := make([]cancellationCase, 2)
	for index := range cancellationCases {
		label := fmt.Sprintf("cancel-%d", index)
		payload := v.bytes(32<<10 + index*4093)
		generated, fifoPath, fixtureErr := v.makeFIFOFixture(directory, label+" fixture", payload)
		if fixtureErr != nil {
			return fixtureErr
		}
		destinationDirectory := filepath.Join(directory, label+" destination")
		if err := prepareCandidateWritableDirectory(destinationDirectory); err != nil {
			return err
		}
		item := cancellationCase{
			label: label, fixture: generated, fifo: fifoPath,
			destination: filepath.Join(destinationDirectory, "artifact.bin"),
		}
		if index == 0 {
			item.hadDestination = true
			item.sentinel = append([]byte("cancellation-sentinel:"), v.bytes(211)...)
			if err := os.WriteFile(item.destination, item.sentinel, 0o640); err != nil {
				return err
			}
		}
		status, result, raw, submitErr := svc.submit(jobSpec{
			RequestID: v.token(label), Manifest: generated.Manifest,
			Destination: item.destination, MaxAttempts: 2,
		})
		if submitErr != nil || status != http.StatusAccepted || result.Job.ID == "" {
			return fmt.Errorf("%s submit status=%d err=%v body=%s", label, status, submitErr, strings.TrimSpace(string(raw)))
		}
		item.jobID = result.Job.ID
		cancellationCases[index] = item
	}

	openedWriters := make(chan fifoOpenResult, len(cancellationCases))
	for _, item := range cancellationCases {
		go func(path string) {
			file, openErr := os.OpenFile(path, os.O_WRONLY, 0)
			openedWriters <- fifoOpenResult{path: path, file: file, err: openErr}
		}(item.fifo)
	}
	writers := make(map[string]*os.File, len(cancellationCases))
	for range cancellationCases {
		select {
		case opened := <-openedWriters:
			if opened.err != nil {
				return opened.err
			}
			writers[opened.path] = opened.file
		case <-time.After(3 * time.Second):
			return errors.New("publishers did not enter the controlled cancellation fixtures")
		}
	}

	signalProcessGroup(svc.cmd.Process.Pid, syscall.SIGTERM)
	listenerDeadline := time.Now().Add(2 * time.Second)
	for {
		_, _, healthErr := svc.requestJSON(http.MethodGet, "/v1/health", nil)
		if healthErr != nil {
			break
		}
		if time.Now().After(listenerDeadline) {
			return errors.New("relay listener did not close after cancellation signal")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// http.Server.Shutdown closes the listener before Engine.Close cancels the
	// engine context. Leave a small scheduling allowance for that adjacent call.
	time.Sleep(50 * time.Millisecond)
	for _, item := range cancellationCases {
		writer := writers[item.fifo]
		if _, err := writer.Write(item.fixture.Artifact); err != nil {
			_ = writer.Close()
			return fmt.Errorf("release %s cancellation fixture: %w", item.label, err)
		}
		if err := writer.Close(); err != nil {
			return fmt.Errorf("close %s cancellation fixture: %w", item.label, err)
		}
	}
	waitErr, awaitErr := svc.await(5 * time.Second)
	if awaitErr != nil || waitErr != nil {
		return fmt.Errorf("cancelled service exit: %v", errors.Join(waitErr, awaitErr))
	}
	for _, item := range cancellationCases {
		if item.hadDestination {
			observed, err := os.ReadFile(item.destination)
			if err != nil || !bytes.Equal(observed, item.sentinel) {
				return fmt.Errorf("%s cancellation changed existing destination: bytes=%d err=%v", item.label, len(observed), err)
			}
		} else if _, err := os.Stat(item.destination); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s cancellation created absent destination: %v", item.label, err)
		}
		names, err := directoryNames(filepath.Dir(item.destination))
		expectedEntries := 0
		if item.hadDestination {
			expectedEntries = 1
		}
		if err != nil || len(names) != expectedEntries || (expectedEntries == 1 && names[0] != filepath.Base(item.destination)) {
			return fmt.Errorf("%s cancellation left publication residue: entries=%v err=%v", item.label, names, err)
		}
	}
	receipts, err := readReceipts(filepath.Join(cfg.StateDir, "receipts.jsonl"))
	if err != nil {
		return err
	}
	if len(receipts) != 2 {
		return fmt.Errorf("cancellation changed successful receipt count: %d", len(receipts))
	}
	for _, receipt := range receipts {
		for _, item := range cancellationCases {
			if receipt.JobID == item.jobID {
				return fmt.Errorf("cancelled job wrote a success receipt: %+v", receipt)
			}
		}
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
	svc, err := startService(v.binDir, configPath, &cfg, filepath.Join(directory, "logs"))
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

func testManifestValidationAndContainment(v *verifier) error {
	directory := filepath.Join(v.root, "manifest validation")
	if err := prepareTestDirectory(directory); err != nil {
		return err
	}
	cfg := baseConfig()
	cfg.WorkerCount = 2
	cfg.MaxAttempts = 1
	cfg.RetryBaseMS = 5
	configPath, cfg, err := v.prepareConfig(directory, cfg)
	if err != nil {
		return err
	}
	svc, err := startService(v.binDir, configPath, &cfg, filepath.Join(directory, "logs"))
	if err != nil {
		return err
	}
	defer svc.kill()

	cases := []struct {
		name string
		kind string
	}{
		{"wrong version", "wrong-version"},
		{"unknown field", "unknown-field"},
		{"trailing data", "trailing-data"},
		{"multiple JSON values", "multiple-values"},
		{"absolute chunk path", "absolute-path"},
		{"parent traversal", "parent-traversal"},
		{"non-canonical chunk path", "non-canonical-path"},
		{"duplicate chunk path", "duplicate-path"},
		{"empty chunk path", "empty-path"},
		{"empty chunk list", "empty-chunks"},
		{"too many chunks", "too-many-chunks"},
		{"negative artifact size", "negative-artifact-size"},
		{"negative chunk size", "negative-chunk-size"},
		{"chunk size total overflow", "size-overflow"},
		{"chunk size total mismatch", "size-mismatch"},
		{"invalid artifact digest", "invalid-artifact-digest"},
		{"uppercase artifact digest", "uppercase-artifact-digest"},
		{"invalid chunk digest", "invalid-chunk-digest"},
		{"uppercase chunk digest", "uppercase-chunk-digest"},
		{"missing chunk", "missing-chunk"},
		{"chunk content mismatch", "chunk-content-mismatch"},
		{"artifact digest mismatch", "artifact-digest-mismatch"},
		{"oversized manifest", "oversized-manifest"},
	}

	payload := v.bytes(v.intBetween(41, 113))
	payloadDigest := fmt.Sprintf("%x", sha256.Sum256(payload))
	emptyDigest := fmt.Sprintf("%x", sha256.Sum256(nil))
	receiptPath := filepath.Join(cfg.StateDir, "receipts.jsonl")
	for index, item := range cases {
		generated, err := v.makeFixture(
			directory,
			fmt.Sprintf("case %02d %s", index, item.name),
			[][]byte{payload, payload},
		)
		if err != nil {
			return fmt.Errorf("%s fixture: %w", item.name, err)
		}
		firstRelative, err := filepath.Rel(generated.Dir, generated.ChunkPaths[0])
		if err != nil {
			return err
		}
		secondRelative, err := filepath.Rel(generated.Dir, generated.ChunkPaths[1])
		if err != nil {
			return err
		}
		manifest := manifestFile{
			Version:        1,
			ArtifactSize:   generated.ArtifactSize,
			ArtifactSHA256: generated.ArtifactSHA,
			Chunks: []manifestChunk{
				{Path: firstRelative, Size: int64(len(payload)), SHA256: payloadDigest},
				{Path: secondRelative, Size: int64(len(payload)), SHA256: payloadDigest},
			},
		}
		var rawManifest []byte
		var containmentPath string
		var containmentBytes []byte

		switch item.kind {
		case "wrong-version":
			manifest.Version = 2
		case "unknown-field":
			base, marshalErr := json.Marshal(manifest)
			if marshalErr != nil {
				return marshalErr
			}
			rawManifest = append(rawManifest, base[:len(base)-1]...)
			rawManifest = append(rawManifest, []byte(`,"unknown":true}`)...)
		case "trailing-data":
			base, marshalErr := json.Marshal(manifest)
			if marshalErr != nil {
				return marshalErr
			}
			rawManifest = append(base, []byte(" trailing")...)
		case "multiple-values":
			base, marshalErr := json.Marshal(manifest)
			if marshalErr != nil {
				return marshalErr
			}
			rawManifest = append(base, []byte("\n{}\n")...)
		case "absolute-path":
			manifest.Chunks[0].Path = string(filepath.Separator) + firstRelative
		case "parent-traversal":
			containmentPath = filepath.Join(directory, fmt.Sprintf("outside traversal %02d.bin", index))
			containmentBytes = append([]byte(nil), payload...)
			if err := writeCandidateReadableFile(containmentPath, containmentBytes); err != nil {
				return err
			}
			manifest.Chunks[0].Path = filepath.Join("..", filepath.Base(containmentPath))
		case "non-canonical-path":
			nested := filepath.Join(generated.Dir, "chunks with spaces", "nested")
			if err := prepareCandidateReadableDirectory(nested); err != nil {
				return err
			}
			manifest.Chunks[0].Path = strings.Join(
				[]string{"chunks with spaces", "nested", "..", filepath.Base(generated.ChunkPaths[0])},
				string(filepath.Separator),
			)
		case "duplicate-path":
			manifest.Chunks[1].Path = manifest.Chunks[0].Path
		case "empty-path":
			manifest.Chunks[0].Path = ""
		case "empty-chunks":
			manifest.ArtifactSize = 0
			manifest.ArtifactSHA256 = emptyDigest
			manifest.Chunks = []manifestChunk{}
		case "too-many-chunks":
			manyDirectory := filepath.Join(generated.Dir, "many empty chunks")
			if err := prepareCandidateReadableDirectory(manyDirectory); err != nil {
				return err
			}
			manifest.ArtifactSize = 0
			manifest.ArtifactSHA256 = emptyDigest
			manifest.Chunks = make([]manifestChunk, 0, 4097)
			for chunkIndex := 0; chunkIndex < 4097; chunkIndex++ {
				name := filepath.Join("many empty chunks", fmt.Sprintf("part-%04d.bin", chunkIndex))
				if err := writeCandidateReadableFile(filepath.Join(generated.Dir, name), nil); err != nil {
					return fmt.Errorf("create maximum-count probe %d: %w", chunkIndex, err)
				}
				manifest.Chunks = append(manifest.Chunks, manifestChunk{Path: name, SHA256: emptyDigest})
			}
		case "negative-artifact-size":
			manifest.ArtifactSize = -1
		case "negative-chunk-size":
			manifest.Chunks[0].Size = -1
		case "size-overflow":
			manifest.Chunks[0].Size = int64(^uint64(0) >> 1)
			manifest.Chunks[1].Size = 1
			manifest.ArtifactSize = 0
		case "size-mismatch":
			manifest.ArtifactSize++
		case "invalid-artifact-digest":
			manifest.ArtifactSHA256 = strings.Repeat("g", 64)
		case "uppercase-artifact-digest":
			manifest.ArtifactSHA256 = "A" + manifest.ArtifactSHA256[1:]
		case "invalid-chunk-digest":
			manifest.Chunks[0].SHA256 = strings.Repeat("g", 64)
		case "uppercase-chunk-digest":
			manifest.Chunks[0].SHA256 = "A" + manifest.Chunks[0].SHA256[1:]
		case "missing-chunk":
			if err := os.Remove(generated.ChunkPaths[1]); err != nil {
				return err
			}
		case "chunk-content-mismatch":
			corrupt := append([]byte(nil), payload...)
			corrupt[len(corrupt)/2] ^= 0x80
			if err := writeCandidateReadableFile(generated.ChunkPaths[1], corrupt); err != nil {
				return err
			}
		case "artifact-digest-mismatch":
			if manifest.ArtifactSHA256[0] == '0' {
				manifest.ArtifactSHA256 = "1" + manifest.ArtifactSHA256[1:]
			} else {
				manifest.ArtifactSHA256 = "0" + manifest.ArtifactSHA256[1:]
			}
		case "oversized-manifest":
			base, marshalErr := json.Marshal(manifest)
			if marshalErr != nil {
				return marshalErr
			}
			rawManifest = append(base, bytes.Repeat([]byte(" "), (8<<20)+1-len(base))...)
		default:
			return fmt.Errorf("unknown manifest case kind %q", item.kind)
		}

		if rawManifest == nil {
			rawManifest, err = json.Marshal(manifest)
			if err != nil {
				return err
			}
		}
		if err := writeCandidateReadableFile(generated.Manifest, rawManifest); err != nil {
			return fmt.Errorf("%s manifest: %w", item.name, err)
		}

		destinationDirectory := filepath.Join(directory, fmt.Sprintf("destination %02d", index))
		if err := prepareCandidateWritableDirectory(destinationDirectory); err != nil {
			return err
		}
		destination := filepath.Join(destinationDirectory, "preserve.bin")
		destinationSentinel := append([]byte("pre-existing:"+item.name+":"), v.bytes(73)...)
		if err := os.WriteFile(destination, destinationSentinel, 0o640); err != nil {
			return err
		}
		beforeReceipts, err := readReceipts(receiptPath)
		if err != nil {
			return err
		}

		requestID := v.token("invalid-manifest")
		status, submitted, raw, err := svc.submit(jobSpec{
			RequestID: requestID, Manifest: generated.Manifest,
			Destination: destination, MaxAttempts: 1,
		})
		if err != nil || status != http.StatusAccepted || submitted.Existing || submitted.Job.ID == "" {
			return fmt.Errorf("%s submit status=%d result=%+v err=%v body=%s", item.name, status, submitted, err, strings.TrimSpace(string(raw)))
		}
		failed, err := waitTerminal(svc, submitted.Job.ID, 12*time.Second)
		if err != nil {
			return fmt.Errorf("%s terminal state: %w", item.name, err)
		}
		if failed.Status != "failed" || failed.Attempts != 1 {
			return fmt.Errorf("%s invalid manifest reached unexpected terminal state: %+v", item.name, failed)
		}
		preserved, err := os.ReadFile(destination)
		if err != nil || !bytes.Equal(preserved, destinationSentinel) {
			return fmt.Errorf("%s changed pre-existing destination: bytes=%d err=%v", item.name, len(preserved), err)
		}
		entries, err := directoryNames(destinationDirectory)
		if err != nil || len(entries) != 1 || entries[0] != filepath.Base(destination) {
			return fmt.Errorf("%s left publication residue: entries=%v err=%v", item.name, entries, err)
		}
		manifestAfter, err := os.ReadFile(generated.Manifest)
		if err != nil || !bytes.Equal(manifestAfter, rawManifest) {
			return fmt.Errorf("%s changed verifier manifest: bytes=%d err=%v", item.name, len(manifestAfter), err)
		}
		if containmentPath != "" {
			observed, readErr := os.ReadFile(containmentPath)
			if readErr != nil || !bytes.Equal(observed, containmentBytes) {
				return fmt.Errorf("%s changed traversal sentinel: bytes=%d err=%v", item.name, len(observed), readErr)
			}
		}
		afterReceipts, err := readReceipts(receiptPath)
		if err != nil {
			return err
		}
		if len(afterReceipts) != len(beforeReceipts) {
			return fmt.Errorf("%s wrote a receipt for failed work: before=%d after=%d", item.name, len(beforeReceipts), len(afterReceipts))
		}
		for _, observed := range afterReceipts {
			if observed.JobID == submitted.Job.ID || observed.RequestID == requestID {
				return fmt.Errorf("%s wrote a receipt for failed job: %+v", item.name, observed)
			}
		}
	}

	if err := svc.stop(); err != nil {
		return err
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
	svc, err := startService(v.binDir, configPath, &cfg, filepath.Join(directory, "logs-one"))
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
	if err := assertExactReceipts(filepath.Join(cfg.StateDir, "receipts.jsonl"), []job{completed}); err != nil {
		return fmt.Errorf("idempotent completion receipt: %w", err)
	}

	manifestLexicalDir := filepath.Join(generated.Dir, "lexical segment")
	destinationDir := filepath.Dir(spec.Destination)
	destinationLexicalDir := filepath.Join(destinationDir, "lexical segment")
	if err := prepareCandidateReadableDirectory(manifestLexicalDir); err != nil {
		return err
	}
	if err := prepareCandidateWritableDirectory(destinationLexicalDir); err != nil {
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
	restarted, err := startService(v.binDir, configPath, &cfg, filepath.Join(directory, "logs-two"))
	if err != nil {
		return err
	}
	defer restarted.kill()
	if err := checkMatrix("after restart", restarted); err != nil {
		return err
	}
	recovered, err := restarted.getJob(jobID)
	if err != nil {
		return err
	}
	if err := assertExactReceipts(filepath.Join(cfg.StateDir, "receipts.jsonl"), []job{recovered}); err != nil {
		return fmt.Errorf("restarted idempotent completion receipt: %w", err)
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
	svc, err := startService(v.binDir, configPath, &cfg, filepath.Join(directory, "logs-one"))
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
		beforeStats, statsErr := svc.readStats()
		if statsErr != nil {
			return statsErr
		}
		walPath := filepath.Join(cfg.StateDir, "events.wal")
		beforeWAL, readErr := os.ReadFile(walPath)
		if readErr != nil {
			return readErr
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
			afterStats, statsErr := svc.readStats()
			if statsErr != nil {
				return statsErr
			}
			afterWAL, readErr := os.ReadFile(walPath)
			if readErr != nil {
				return readErr
			}
			if afterStats.Runtime.Accepted != beforeStats.Runtime.Accepted ||
				afterStats.Runtime.WALAppends != beforeStats.Runtime.WALAppends ||
				afterStats.Runtime.WALBytes != beforeStats.Runtime.WALBytes ||
				afterStats.LastSequence != beforeStats.LastSequence ||
				!bytes.Equal(afterWAL, beforeWAL) {
				return fmt.Errorf("queue_full mutated durable admission state for %q: before_stats=%+v after_stats=%+v wal_before=%d wal_after=%d",
					candidate.RequestID, beforeStats, afterStats, len(beforeWAL), len(afterWAL))
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
	completedJobs := []job{blockedJob}
	for _, id := range acceptedIDs {
		completed, waitErr := waitTerminal(svc, id, 12*time.Second)
		if waitErr != nil || completed.Status != "succeeded" {
			return fmt.Errorf("admitted queued job %q completion=%+v err=%v", id, completed, waitErr)
		}
		completedJobs = append(completedJobs, completed)
	}

	status, immediate, raw, err := svc.submit(rejected[0])
	if err != nil || status != http.StatusAccepted || immediate.Existing || immediate.Job.ID == "" {
		return fmt.Errorf("queue_full retry did not become first acceptance: status=%d result=%+v err=%v body=%s", status, immediate, err, strings.TrimSpace(string(raw)))
	}
	immediateJob, err := waitTerminal(svc, immediate.Job.ID, 8*time.Second)
	if err != nil || immediateJob.Status != "succeeded" {
		return fmt.Errorf("queue_full retry completion=%+v err=%v", immediateJob, err)
	}
	completedJobs = append(completedJobs, immediateJob)
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
	restarted, err := startService(v.binDir, configPath, &cfg, filepath.Join(directory, "logs-two"))
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
	completedJobs = append(completedJobs, afterRestartJob)
	if err := assertExactReceipts(filepath.Join(cfg.StateDir, "receipts.jsonl"), completedJobs); err != nil {
		return fmt.Errorf("queue admission completion receipts: %w", err)
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
	if err := prepareCandidateWritableDirectory(cfg.StateDir); err != nil {
		return err
	}
	// Make the receipt ledger much larger than the WAL before relayqd opens it.
	// A process-wide RLIMIT_FSIZE can then permit the next success frame while
	// deterministically rejecting any append at the ledger's existing offset.
	var historical bytes.Buffer
	encoder := json.NewEncoder(&historical)
	for index := 0; index < 256; index++ {
		value := receipt{
			Version:        1,
			JobID:          fmt.Sprintf("historical-job-%03d", index),
			RequestID:      fmt.Sprintf("historical-request-%03d", index),
			Destination:    filepath.Join(directory, "historical", strings.Repeat("x", 1024), fmt.Sprintf("artifact-%03d.bin", index)),
			ArtifactSize:   int64(index + 1),
			ArtifactSHA256: strings.Repeat("a", 64),
			CompletedAt:    time.Unix(1700000000+int64(index), 0).UTC(),
		}
		if err := encoder.Encode(value); err != nil {
			return err
		}
	}
	receiptPath := filepath.Join(cfg.StateDir, "receipts.jsonl")
	if err := os.WriteFile(receiptPath, historical.Bytes(), 0o600); err != nil {
		return err
	}
	svc, err := startService(v.binDir, configPath, &cfg, filepath.Join(directory, "logs-one"))
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
	limit := uint64(walInfo.Size()) + 64<<10
	receiptInfo, err := os.Stat(receiptPath)
	if err != nil {
		_ = fifoWriter.Close()
		return err
	}
	if uint64(receiptInfo.Size()) <= limit {
		_ = fifoWriter.Close()
		return fmt.Errorf("historical receipt ledger %d does not exceed injected limit %d", receiptInfo.Size(), limit)
	}
	if err := setProcessFileSizeLimit(svc.cmd.Process.Pid, limit); err != nil {
		_ = fifoWriter.Close()
		return fmt.Errorf("separate success and receipt writes: %w", err)
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
	artifactBefore, err := os.Stat(spec.Destination)
	if err != nil {
		return err
	}

	walPath := filepath.Join(cfg.StateDir, "events.wal")
	var durableSuccess durableEvent
	deadline = time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		scan, scanErr := scanWAL(walPath, 0)
		if scanErr == nil {
			for _, event := range scan.Events {
				if event.Job.ID == submitted.Job.ID && event.Type == "job_succeeded" {
					durableSuccess = event
					break
				}
			}
		}
		if durableSuccess.Job.ID != "" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if durableSuccess.Job.ID == "" {
		return errors.New("injected crash window never exposed a complete durable job_succeeded frame")
	}
	if durableSuccess.Job.Attempts != 1 || durableSuccess.Job.Status != "succeeded" || durableSuccess.Job.ArtifactSHA != generated.ArtifactSHA {
		return fmt.Errorf("durable success frame is inconsistent: %+v", durableSuccess)
	}
	beforeKillReceipts, err := readReceipts(receiptPath)
	if err != nil {
		return err
	}
	for _, value := range beforeKillReceipts {
		if value.JobID == submitted.Job.ID || value.RequestID == spec.RequestID {
			return fmt.Errorf("target receipt was written despite injected ledger failure: %+v", value)
		}
	}
	svc.kill()

	address, err := reserveAddress()
	if err != nil {
		return err
	}
	cfg.Listen = address
	if err := writeJSON(configPath, cfg); err != nil {
		return err
	}
	restarted, err := startService(v.binDir, configPath, &cfg, filepath.Join(directory, "logs-two"))
	if err != nil {
		return fmt.Errorf("restart after receipt-edge kill: %w", err)
	}
	defer restarted.kill()
	recovered, err := restarted.getJob(submitted.Job.ID)
	if err != nil {
		return err
	}
	if recovered.Status != "succeeded" || recovered.Attempts != durableSuccess.Job.Attempts || recovered.ArtifactSHA != generated.ArtifactSHA || !recovered.CompletedAt.Equal(durableSuccess.Job.CompletedAt) {
		return fmt.Errorf("receipt-edge recovery changed successful job: %+v", recovered)
	}
	// A nonblocking FIFO writer succeeds only while a reader is present. Polling
	// it proves recovery did not enqueue and re-run the already durable job.
	deadline = time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		fd, openErr := syscall.Open(fifoPath, syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
		if openErr == nil {
			_ = syscall.Close(fd)
			return errors.New("recovery reopened the manifest FIFO and attempted a second publication")
		}
		if !errors.Is(openErr, syscall.ENXIO) {
			return fmt.Errorf("probe recovered FIFO reader: %w", openErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	artifactAfter, err := os.Stat(spec.Destination)
	if err != nil {
		return err
	}
	afterBytes, err := os.ReadFile(spec.Destination)
	if err != nil || !bytes.Equal(afterBytes, payload) || !os.SameFile(artifactBefore, artifactAfter) {
		return fmt.Errorf("recovery republished the artifact: bytes=%d same_file=%v err=%v", len(afterBytes), os.SameFile(artifactBefore, artifactAfter), err)
	}
	jobs, err := restarted.listByRequest(spec.RequestID)
	if err != nil || len(jobs) != 1 || jobs[0].ID != submitted.Job.ID {
		return fmt.Errorf("receipt-edge recovery changed identity: jobs=%+v err=%v", jobs, err)
	}
	receipts, err := readReceipts(receiptPath)
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
	if err := assertExactReceipts(receiptPath, []job{recovered}); err != nil {
		return fmt.Errorf("receipt-edge exact completion: %w", err)
	}
	if err := restarted.stop(); err != nil {
		return err
	}
	return nil
}

type fifoOpenResult struct {
	path     string
	file     *os.File
	openedAt time.Time
	err      error
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
	cfg.RetryBaseMS = 1800
	cfg.MaxAttempts = 2
	configPath, cfg, err := v.prepareConfig(directory, cfg)
	if err != nil {
		return err
	}
	svc, err := startService(v.binDir, configPath, &cfg, filepath.Join(directory, "logs"))
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
	updated.WorkerCount = v.intBetween(2, 4)
	updated.RetryBaseMS = v.intBetween(220, 360)
	updated.MaxAttempts = v.intBetween(3, 6)
	updated.MaxRequestBytes = int64(v.intBetween(5000, 7000))
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
	if after.Config != (configSnapshot{Generation: 2, configFile: updated}) || after.Runtime.ActiveWorkerLimit != int64(updated.WorkerCount) {
		return fmt.Errorf("mutable reload not coherent: %+v", after)
	}

	unchangedWorkers := updated
	unchangedWorkers.RetryBaseMS = v.intBetween(600, 650)
	unchangedWorkers.MaxAttempts = v.intBetween(7, 10)
	unchangedWorkers.MaxRequestBytes = int64(v.intBetween(9000, 12000))
	if err := writeJSON(configPath, unchangedWorkers); err != nil {
		return err
	}
	status, raw, err = svc.requestJSON(http.MethodPost, "/v1/admin/reload", nil)
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("unchanged-worker reload status=%d err=%v body=%s", status, err, strings.TrimSpace(string(raw)))
	}
	unchangedStats, err := svc.readStats()
	if err != nil {
		return err
	}
	if unchangedStats.Config != (configSnapshot{Generation: 3, configFile: unchangedWorkers}) ||
		unchangedStats.Runtime.ActiveWorkerLimit != int64(unchangedWorkers.WorkerCount) || unchangedStats.Runtime.ActiveWorkers != 2 {
		return fmt.Errorf("unchanged-worker reload not coherent: %+v", unchangedStats)
	}

	scaledDown := unchangedWorkers
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
	if downStats.Config != (configSnapshot{Generation: 4, configFile: scaledDown}) || downStats.Runtime.ActiveWorkerLimit != 1 || downStats.Runtime.ActiveWorkers != 2 {
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
	reloadCompleted := make([]job, 0, 5)
	for _, id := range []string{firstSubmit.Job.ID, secondSubmit.Job.ID, thirdSubmit.Job.ID} {
		value, err := waitTerminal(svc, id, 5*time.Second)
		if err != nil {
			return err
		}
		if value.Status != "succeeded" {
			return fmt.Errorf("FIFO job failed after reload: %+v", value)
		}
		reloadCompleted = append(reloadCompleted, value)
	}

	verifyRetryTiming := func(label string, current configFile, upperSlack time.Duration) (job, fixture, error) {
		retryData := v.bytes(7777)
		retryFixture, chunkPath, fixtureErr := v.makeFIFOFixture(directory, label+" fixture", retryData)
		if fixtureErr != nil {
			return job{}, fixture{}, fixtureErr
		}
		retryStatus, retrySubmit, retryRaw, submitErr := svc.submit(jobSpec{
			RequestID: v.token(label), Manifest: retryFixture.Manifest,
			Destination: filepath.Join(directory, "retry archive", label+".bin"),
		})
		if submitErr != nil || retryStatus != http.StatusAccepted {
			return job{}, fixture{}, fmt.Errorf("%s submit status=%d err=%v body=%s", label, retryStatus, submitErr, strings.TrimSpace(string(retryRaw)))
		}
		firstWriterResult := make(chan fifoOpenResult, 1)
		go func() {
			file, openErr := os.OpenFile(chunkPath, os.O_WRONLY, 0)
			firstWriterResult <- fifoOpenResult{path: chunkPath, file: file, openedAt: time.Now(), err: openErr}
		}()
		var firstWriter fifoOpenResult
		select {
		case firstWriter = <-firstWriterResult:
		case <-time.After(3 * time.Second):
			return job{}, fixture{}, fmt.Errorf("%s first attempt did not open the controlled chunk", label)
		}
		if firstWriter.err != nil {
			return job{}, fixture{}, firstWriter.err
		}
		corrupt := append([]byte(nil), retryData...)
		corrupt[len(corrupt)/2] ^= 0x80
		if _, writeErr := firstWriter.file.Write(corrupt); writeErr != nil {
			_ = firstWriter.file.Close()
			return job{}, fixture{}, writeErr
		}
		if closeErr := firstWriter.file.Close(); closeErr != nil {
			return job{}, fixture{}, closeErr
		}
		failureReleasedAt := time.Now()
		retrying, waitErr := waitForJob(svc, retrySubmit.Job.ID, 2*time.Second, func(value job) bool {
			return value.Status == "retry_wait" && value.Attempts == 1
		})
		if waitErr != nil {
			return job{}, fixture{}, waitErr
		}
		if retrying.Spec.MaxAttempts != current.MaxAttempts {
			return job{}, fixture{}, fmt.Errorf("%s did not use reloaded default max_attempts: %+v", label, retrying.Spec)
		}
		if removeErr := os.Remove(chunkPath); removeErr != nil {
			return job{}, fixture{}, removeErr
		}
		if fifoErr := syscall.Mkfifo(chunkPath, 0o600); fifoErr != nil {
			return job{}, fixture{}, fifoErr
		}
		if chownErr := os.Chown(chunkPath, 0, int(activeCandidateGID)); chownErr != nil {
			return job{}, fixture{}, chownErr
		}
		if chmodErr := os.Chmod(chunkPath, 0o640); chmodErr != nil {
			return job{}, fixture{}, chmodErr
		}
		openedWriter := make(chan fifoOpenResult, 1)
		go func() {
			file, openErr := os.OpenFile(chunkPath, os.O_WRONLY, 0)
			openedWriter <- fifoOpenResult{path: chunkPath, file: file, openedAt: time.Now(), err: openErr}
		}()
		base := time.Duration(current.RetryBaseMS) * time.Millisecond
		minimum := base - 35*time.Millisecond
		maximum := time.Duration(current.RetryBaseMS)*time.Millisecond + upperSlack
		remaining := time.Until(failureReleasedAt.Add(maximum))
		if remaining <= 0 {
			return job{}, fixture{}, fmt.Errorf("%s exhausted retry observation window before FIFO setup", label)
		}
		var opened fifoOpenResult
		select {
		case opened = <-openedWriter:
		case <-time.After(remaining):
			return job{}, fixture{}, fmt.Errorf("%s retry did not reopen the controlled chunk within %s", label, maximum)
		}
		if opened.err != nil {
			return job{}, fixture{}, opened.err
		}
		elapsed := opened.openedAt.Sub(failureReleasedAt)
		if elapsed < minimum || elapsed >= maximum {
			_ = opened.file.Close()
			return job{}, fixture{}, fmt.Errorf("%s retry_base_ms=%d opened outside [%s,%s): elapsed=%s", label, current.RetryBaseMS, minimum, maximum, elapsed)
		}
		if _, writeErr := opened.file.Write(retryData); writeErr != nil {
			_ = opened.file.Close()
			return job{}, fixture{}, writeErr
		}
		if closeErr := opened.file.Close(); closeErr != nil {
			return job{}, fixture{}, closeErr
		}
		retried, terminalErr := waitTerminal(svc, retrySubmit.Job.ID, 5*time.Second)
		if terminalErr != nil {
			return job{}, fixture{}, terminalErr
		}
		if retried.Status != "succeeded" || retried.Attempts != 2 {
			return job{}, fixture{}, fmt.Errorf("%s retry completion mismatch: %+v", label, retried)
		}
		return retried, retryFixture, nil
	}

	fastRetry, retryFixture, err := verifyRetryTiming("reload-retry-fast", scaledDown, 300*time.Millisecond)
	if err != nil {
		return err
	}
	reloadCompleted = append(reloadCompleted, fastRetry)

	slowerRetryConfig := scaledDown
	slowerRetryConfig.RetryBaseMS = v.intBetween(1100, 1200)
	if err := writeJSON(configPath, slowerRetryConfig); err != nil {
		return err
	}
	status, raw, err = svc.requestJSON(http.MethodPost, "/v1/admin/reload", nil)
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("second retry-base reload status=%d err=%v body=%s", status, err, strings.TrimSpace(string(raw)))
	}
	slowerStats, err := svc.readStats()
	if err != nil {
		return err
	}
	if slowerStats.Config != (configSnapshot{Generation: 5, configFile: slowerRetryConfig}) || slowerStats.Runtime.ActiveWorkerLimit != 1 {
		return fmt.Errorf("second retry-base reload not coherent: %+v", slowerStats)
	}
	slowRetry, _, err := verifyRetryTiming("reload-retry-slow", slowerRetryConfig, 350*time.Millisecond)
	if err != nil {
		return err
	}
	reloadCompleted = append(reloadCompleted, slowRetry)

	boundarySpec := jobSpec{
		RequestID: v.token("reload-size-within"), Manifest: retryFixture.Manifest,
		Destination: "d", MaxAttempts: 1,
	}
	baseRaw, err := json.Marshal(boundarySpec)
	if err != nil {
		return err
	}
	withinPadding := int(slowerRetryConfig.MaxRequestBytes) - len(baseRaw) - 64
	if withinPadding < 1 {
		return fmt.Errorf("randomized max_request_bytes is too small for boundary probe: %d", slowerRetryConfig.MaxRequestBytes)
	}
	boundarySpec.Destination = strings.Repeat("d", withinPadding)
	withinRaw, err := json.Marshal(boundarySpec)
	if err != nil {
		return err
	}
	if int64(len(withinRaw)) >= slowerRetryConfig.MaxRequestBytes {
		return fmt.Errorf("within-limit probe length=%d limit=%d", len(withinRaw), slowerRetryConfig.MaxRequestBytes)
	}
	status, _, raw, err = svc.submit(boundarySpec)
	if err != nil || status != http.StatusAccepted {
		return fmt.Errorf("reloaded max_request_bytes rejected within-limit request: size=%d limit=%d status=%d err=%v body=%s",
			len(withinRaw), slowerRetryConfig.MaxRequestBytes, status, err, strings.TrimSpace(string(raw)))
	}
	overSpec := boundarySpec
	overSpec.RequestID = v.token("reload-size-over")
	overSpec.Destination = strings.Repeat("d", int(slowerRetryConfig.MaxRequestBytes)+512)
	oversized, err := json.Marshal(overSpec)
	if err != nil {
		return err
	}
	status, raw, err = svc.requestRaw(http.MethodPost, "/v1/jobs", "application/json", oversized)
	if err != nil || status != http.StatusBadRequest {
		return fmt.Errorf("reloaded max_request_bytes=%d not enforced for size=%d: status=%d err=%v body=%s",
			slowerRetryConfig.MaxRequestBytes, len(oversized), status, err, strings.TrimSpace(string(raw)))
	}
	if err := assertExactReceipts(filepath.Join(cfg.StateDir, "receipts.jsonl"), reloadCompleted); err != nil {
		return fmt.Errorf("reload completion receipts: %w", err)
	}
	if err := svc.stop(); err != nil {
		return err
	}
	return nil
}

func testPeriodicSnapshotAndListenerPolicy(v *verifier) error {
	directory := filepath.Join(v.root, "periodic snapshot listener")
	if err := prepareTestDirectory(directory); err != nil {
		return err
	}

	portBase := v.intBetween(20000, 45000)
	for index, listen := range []string{
		fmt.Sprintf("0.0.0.0:%d", portBase),
		fmt.Sprintf("[::]:%d", portBase+1),
		fmt.Sprintf("localhost:%d", portBase+2),
	} {
		caseDirectory := filepath.Join(directory, fmt.Sprintf("listener case %d", index))
		if err := prepareTestDirectory(caseDirectory); err != nil {
			return err
		}
		candidate := baseConfig()
		candidate.Listen = listen
		candidate.StateDir = filepath.Join(caseDirectory, "state")
		configPath := filepath.Join(caseDirectory, "relay.json")
		if err := writeJSON(configPath, candidate); err != nil {
			return err
		}
		output, err := expectStartupFailure(v.binDir, configPath, &candidate, 1500*time.Millisecond)
		if err != nil {
			return fmt.Errorf("non-loopback listener %q did not fail closed: %w output=%s", listen, err, strings.TrimSpace(output))
		}
		if !strings.Contains(strings.ToLower(output), "loopback") {
			return fmt.Errorf("non-loopback listener %q failed for the wrong reason: %s", listen, strings.TrimSpace(output))
		}
	}

	periodicDirectory := filepath.Join(directory, "automatic compaction")
	cfg := baseConfig()
	cfg.WorkerCount = 4
	cfg.SyncWAL = true
	cfg.SnapshotIntervalMS = v.intBetween(70, 110)
	configPath, cfg, err := v.prepareConfig(periodicDirectory, cfg)
	if err != nil {
		return err
	}
	svc, err := startService(v.binDir, configPath, &cfg, filepath.Join(periodicDirectory, "logs-one"))
	if err != nil {
		return err
	}
	defer svc.kill()

	snapshotPath := filepath.Join(cfg.StateDir, "snapshot.json")
	type periodicObservation struct {
		reads       int
		seen        bool
		maxSequence uint64
		err         error
	}
	observerStop := make(chan struct{})
	observerResult := make(chan periodicObservation, 1)
	var observerStopOnce sync.Once
	stopObserver := func() { observerStopOnce.Do(func() { close(observerStop) }) }
	defer stopObserver()
	go func() {
		result := periodicObservation{}
		var previous uint64
		observe := func() bool {
			observed, exists, readErr := readSnapshot(snapshotPath)
			result.reads++
			if readErr != nil {
				result.err = fmt.Errorf("automatic snapshot was partially visible: %w", readErr)
				return false
			}
			if result.seen && !exists {
				result.err = errors.New("automatic snapshot disappeared after becoming visible")
				return false
			}
			if exists {
				result.seen = true
				if observed.LastSequence < previous {
					result.err = fmt.Errorf("automatic snapshot sequence regressed %d -> %d", previous, observed.LastSequence)
					return false
				}
				previous = observed.LastSequence
				if observed.LastSequence > result.maxSequence {
					result.maxSequence = observed.LastSequence
				}
			}
			return true
		}
		for {
			select {
			case <-observerStop:
				// The main goroutine closes observerStop immediately after it
				// observes the target snapshot. Take one final independent read
				// before reporting so a scheduler handoff cannot leave this
				// observer one valid snapshot generation behind.
				if result.err == nil {
					_ = observe()
				}
				observerResult <- result
				return
			default:
			}
			if !observe() {
				observerResult <- result
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	generated, err := v.makeFixture(periodicDirectory, "periodic fixture", [][]byte{v.bytes(2051), v.bytes(3073)})
	if err != nil {
		return err
	}
	const count = 16
	completed := make([]job, 0, count)
	for index := 0; index < count; index++ {
		status, submitted, raw, submitErr := svc.submit(jobSpec{
			RequestID:   v.token(fmt.Sprintf("periodic-%02d", index)),
			Manifest:    generated.Manifest,
			Destination: filepath.Join(periodicDirectory, "archive", fmt.Sprintf("artifact-%02d.bin", index)),
			MaxAttempts: 2,
		})
		if submitErr != nil || status != http.StatusAccepted {
			return fmt.Errorf("periodic submit %d status=%d err=%v body=%s", index, status, submitErr, strings.TrimSpace(string(raw)))
		}
		value, waitErr := waitTerminal(svc, submitted.Job.ID, 8*time.Second)
		if waitErr != nil || value.Status != "succeeded" {
			return fmt.Errorf("periodic job %d completion=%+v err=%v", index, value, waitErr)
		}
		completed = append(completed, value)
	}
	targetStats, err := svc.readStats()
	if err != nil {
		return err
	}
	targetSequence := targetStats.LastSequence
	deadline := time.Now().Add(4 * time.Second)
	var automaticSnapshot durableSnapshot
	for time.Now().Before(deadline) {
		currentStats, statsErr := svc.readStats()
		observed, exists, snapshotErr := readSnapshot(snapshotPath)
		if statsErr == nil && snapshotErr == nil && exists && currentStats.Runtime.Snapshots >= 2 && observed.LastSequence >= targetSequence {
			automaticSnapshot = observed
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if automaticSnapshot.LastSequence < targetSequence {
		return fmt.Errorf("periodic compactor did not snapshot target sequence %d: snapshot=%+v", targetSequence, automaticSnapshot)
	}
	stopObserver()
	observation := <-observerResult
	if observation.err != nil {
		return observation.err
	}
	if !observation.seen || observation.reads < 5 || observation.maxSequence < targetSequence {
		return fmt.Errorf("automatic snapshot observer did not overlap publication: %+v target=%d", observation, targetSequence)
	}
	if err := assertExactReceipts(filepath.Join(cfg.StateDir, "receipts.jsonl"), completed); err != nil {
		return fmt.Errorf("periodic completion receipts: %w", err)
	}
	if err := svc.stop(); err != nil {
		return err
	}

	finalSnapshot, exists, err := readSnapshot(snapshotPath)
	if err != nil || !exists {
		return fmt.Errorf("automatic snapshot unavailable after shutdown: exists=%v err=%v", exists, err)
	}
	scan, err := scanWAL(filepath.Join(cfg.StateDir, "events.wal"), finalSnapshot.LastSequence)
	if err != nil {
		return fmt.Errorf("automatic snapshot WAL sequence: %w", err)
	}
	durableJobs, err := replayDurableState(finalSnapshot, scan)
	if err != nil {
		return fmt.Errorf("automatic snapshot durable replay: %w", err)
	}
	if len(durableJobs) != count {
		return fmt.Errorf("automatic snapshot replay has %d jobs, expected %d", len(durableJobs), count)
	}
	for index, value := range completed {
		durable, ok := durableJobs[value.ID]
		if !ok || !sameDurableJob(durable, value) {
			return fmt.Errorf("automatic snapshot lost job %d: durable=%+v completed=%+v", index, durable, value)
		}
	}

	address, err := reserveAddress()
	if err != nil {
		return err
	}
	cfg.Listen = address
	if err := writeJSON(configPath, cfg); err != nil {
		return err
	}
	restarted, err := startService(v.binDir, configPath, &cfg, filepath.Join(periodicDirectory, "logs-two"))
	if err != nil {
		return fmt.Errorf("restart after automatic snapshot: %w", err)
	}
	defer restarted.kill()
	for index, value := range completed {
		jobs, listErr := restarted.listByRequest(value.Spec.RequestID)
		if listErr != nil || len(jobs) != 1 || !sameDurableJob(jobs[0], value) {
			return fmt.Errorf("automatic snapshot recovery job %d jobs=%+v err=%v", index, jobs, listErr)
		}
	}
	if err := restarted.stop(); err != nil {
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
	svc, err := startService(v.binDir, configPath, &cfg, filepath.Join(directory, "logs-one"))
	if err != nil {
		return err
	}
	defer svc.kill()
	generated, err := v.makeFixture(directory, "shared fixture", [][]byte{v.bytes(2053), v.bytes(3079)})
	if err != nil {
		return err
	}
	snapshotPath := filepath.Join(cfg.StateDir, "snapshot.json")
	status, raw, err := svc.requestJSON(http.MethodPost, "/v1/admin/compact", nil)
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("prime snapshot status=%d err=%v body=%s", status, err, strings.TrimSpace(string(raw)))
	}
	if _, exists, err := readSnapshot(snapshotPath); err != nil || !exists {
		return fmt.Errorf("prime snapshot is not independently readable: exists=%v err=%v", exists, err)
	}
	type snapshotObservation struct {
		reads       int
		maxSequence uint64
		err         error
	}
	observerStop := make(chan struct{})
	observerResult := make(chan snapshotObservation, 1)
	var observerStopOnce sync.Once
	stopObserver := func() { observerStopOnce.Do(func() { close(observerStop) }) }
	defer stopObserver()
	go func() {
		result := snapshotObservation{}
		var previous uint64
		for {
			select {
			case <-observerStop:
				observerResult <- result
				return
			default:
			}
			observed, exists, readErr := readSnapshot(snapshotPath)
			result.reads++
			if readErr != nil || !exists {
				result.err = fmt.Errorf("snapshot reader observed a partial or missing file: exists=%v err=%v", exists, readErr)
				observerResult <- result
				return
			}
			if observed.LastSequence < previous {
				result.err = fmt.Errorf("snapshot reader observed sequence regression %d -> %d", previous, observed.LastSequence)
				observerResult <- result
				return
			}
			previous = observed.LastSequence
			if observed.LastSequence > result.maxSequence {
				result.maxSequence = observed.LastSequence
			}
			time.Sleep(time.Millisecond)
		}
	}()

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
	stopObserver()
	observation := <-observerResult
	if observation.err != nil {
		return observation.err
	}
	if observation.reads < 5 || observation.maxSequence == 0 {
		return fmt.Errorf("snapshot observer did not overlap compaction: %+v", observation)
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

	snapshot, exists, err := readSnapshot(snapshotPath)
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
	restarted, err := startService(v.binDir, configPath, &cfg, filepath.Join(directory, "logs-two"))
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
	expectedReceipts := make([]job, 0, count+1)
	for _, outcome := range outcomes {
		expectedReceipts = append(expectedReceipts, durableJobs[outcome.jobID])
	}
	expectedReceipts = append(expectedReceipts, durableJobs[sentinelSubmit.Job.ID])
	if err := assertExactReceipts(filepath.Join(cfg.StateDir, "receipts.jsonl"), expectedReceipts); err != nil {
		return fmt.Errorf("concurrent compaction completion receipts: %w", err)
	}
	if err := restarted.stop(); err != nil {
		return err
	}
	return nil
}

func testCompactionCrashRecovery(v *verifier) error {
	directory := filepath.Join(v.root, "compaction crash nonterminal")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	cfg := baseConfig()
	cfg.WorkerCount = 1
	cfg.QueueCapacity = 128
	cfg.RetryBaseMS = 30000
	cfg.MaxAttempts = 3
	cfg.SyncWAL = true
	configPath, cfg, err := v.prepareConfig(directory, cfg)
	if err != nil {
		return err
	}
	svc, err := startService(v.binDir, configPath, &cfg, filepath.Join(directory, "logs-one"))
	if err != nil {
		return err
	}
	initialAlive := true
	defer func() {
		if initialAlive {
			svc.kill()
		}
	}()

	type acceptedRecord struct {
		id               string
		requestID        string
		spec             jobSpec
		artifact         []byte
		artifactSHA      string
		preCrashStatus   string
		expectedAttempts int
	}
	records := make([]acceptedRecord, 0, 14)

	retryPayload := v.bytes(12289)
	retryFixture, err := v.makeFixture(directory, "crash retry fixture", [][]byte{retryPayload})
	if err != nil {
		return err
	}
	if err := os.Remove(retryFixture.ChunkPaths[0]); err != nil {
		return err
	}
	retrySpec := jobSpec{
		RequestID: v.token("crash-retry"), Manifest: retryFixture.Manifest,
		Destination: filepath.Join(directory, "recovered archive", "retry.bin"), MaxAttempts: 3,
	}
	status, retrySubmit, raw, err := svc.submit(retrySpec)
	if err != nil || status != http.StatusAccepted || retrySubmit.Job.ID == "" {
		return fmt.Errorf("crash retry submit status=%d err=%v body=%s", status, err, strings.TrimSpace(string(raw)))
	}
	retrying, err := waitForJob(svc, retrySubmit.Job.ID, 3*time.Second, func(value job) bool {
		return value.Status == "retry_wait" && value.Attempts == 1
	})
	if err != nil {
		return err
	}
	if err := writeCandidateReadableFile(retryFixture.ChunkPaths[0], retryPayload); err != nil {
		return err
	}
	records = append(records, acceptedRecord{
		id: retrySubmit.Job.ID, requestID: retrySpec.RequestID, spec: retrySpec,
		artifact: retryFixture.Artifact, artifactSHA: retryFixture.ArtifactSHA,
		preCrashStatus: retrying.Status, expectedAttempts: 2,
	})

	blockedPayload := v.bytes(24593)
	blockedFixture, blockedFIFO, err := v.makeFIFOFixture(directory, "crash running fixture", blockedPayload)
	if err != nil {
		return err
	}
	blockedSpec := jobSpec{
		RequestID: v.token("crash-running"), Manifest: blockedFixture.Manifest,
		Destination: filepath.Join(directory, "recovered archive", "running.bin"), MaxAttempts: 3,
	}
	status, blockedSubmit, raw, err := svc.submit(blockedSpec)
	if err != nil || status != http.StatusAccepted || blockedSubmit.Job.ID == "" {
		return fmt.Errorf("crash running submit status=%d err=%v body=%s", status, err, strings.TrimSpace(string(raw)))
	}
	blockedWriterResult := make(chan fifoOpenResult, 1)
	go func() {
		file, openErr := os.OpenFile(blockedFIFO, os.O_WRONLY, 0)
		blockedWriterResult <- fifoOpenResult{path: blockedFIFO, file: file, openedAt: time.Now(), err: openErr}
	}()
	var blockedWriter *os.File
	select {
	case opened := <-blockedWriterResult:
		if opened.err != nil {
			return opened.err
		}
		blockedWriter = opened.file
	case <-time.After(3 * time.Second):
		return errors.New("worker did not enter the running crash fixture")
	}
	running, err := waitForJob(svc, blockedSubmit.Job.ID, 2*time.Second, func(value job) bool {
		return value.Status == "running" && value.Attempts == 1
	})
	if err != nil {
		_ = blockedWriter.Close()
		return err
	}
	records = append(records, acceptedRecord{
		id: blockedSubmit.Job.ID, requestID: blockedSpec.RequestID, spec: blockedSpec,
		artifact: blockedFixture.Artifact, artifactSHA: blockedFixture.ArtifactSHA,
		preCrashStatus: running.Status, expectedAttempts: 2,
	})

	compactProgress := make(chan int, 128)
	compactDone := make(chan error, 1)
	go func() {
		for index := 0; index < 100; index++ {
			compactStatus, compactRaw, compactErr := svc.requestJSON(http.MethodPost, "/v1/admin/compact", nil)
			if compactErr != nil || compactStatus != http.StatusOK {
				compactDone <- fmt.Errorf("crash compact %d status=%d err=%v body=%s", index, compactStatus, compactErr, strings.TrimSpace(string(compactRaw)))
				return
			}
			compactProgress <- index + 1
			time.Sleep(5 * time.Millisecond)
		}
		compactDone <- nil
	}()
	select {
	case <-compactProgress:
	case compactErr := <-compactDone:
		_ = blockedWriter.Close()
		return fmt.Errorf("compaction stopped before overlapping submissions: %w", compactErr)
	case <-time.After(3 * time.Second):
		_ = blockedWriter.Close()
		return errors.New("compaction did not begin before pending submissions")
	}

	pendingFixture, err := v.makeFixture(directory, "crash pending fixture", [][]byte{v.bytes(4099), v.bytes(6151)})
	if err != nil {
		_ = blockedWriter.Close()
		return err
	}
	const pendingCount = 12
	for index := 0; index < pendingCount; index++ {
		requestID := v.token(fmt.Sprintf("crash-pending-%02d", index))
		spec := jobSpec{
			RequestID: requestID, Manifest: pendingFixture.Manifest,
			Destination: filepath.Join(directory, "recovered archive", fmt.Sprintf("pending-%02d.bin", index)), MaxAttempts: 3,
		}
		status, result, raw, submitErr := svc.submit(spec)
		if submitErr != nil || status != http.StatusAccepted || result.Job.ID == "" {
			_ = blockedWriter.Close()
			return fmt.Errorf("crash pending %d submit status=%d err=%v body=%s", index, status, submitErr, strings.TrimSpace(string(raw)))
		}
		records = append(records, acceptedRecord{
			id: result.Job.ID, requestID: requestID, spec: spec,
			artifact: pendingFixture.Artifact, artifactSHA: pendingFixture.ArtifactSHA,
			preCrashStatus: "pending", expectedAttempts: 1,
		})
	}

	completedCompactions := 1
	for completedCompactions < 3 {
		select {
		case <-compactProgress:
			completedCompactions++
		case compactErr := <-compactDone:
			_ = blockedWriter.Close()
			return fmt.Errorf("compaction stopped before crash window: %w", compactErr)
		case <-time.After(3 * time.Second):
			_ = blockedWriter.Close()
			return fmt.Errorf("only %d compactions completed before crash", completedCompactions)
		}
	}

	beforeKill := make(map[string]job, len(records))
	statusCounts := make(map[string]int)
	for _, record := range records {
		value, readErr := svc.getJob(record.id)
		if readErr != nil {
			_ = blockedWriter.Close()
			return readErr
		}
		if value.ID != record.id || value.Spec != record.spec || value.Status != record.preCrashStatus {
			_ = blockedWriter.Close()
			return fmt.Errorf("pre-crash job changed identity/spec/state: record=%+v job=%+v", record, value)
		}
		beforeKill[record.id] = value
		statusCounts[value.Status]++
	}
	if statusCounts["retry_wait"] != 1 || statusCounts["running"] != 1 || statusCounts["pending"] != pendingCount {
		_ = blockedWriter.Close()
		return fmt.Errorf("crash window lacks required nonterminal states: %v", statusCounts)
	}

	svc.kill()
	initialAlive = false
	_ = blockedWriter.Close()
	select {
	case <-compactDone:
	case <-time.After(6 * time.Second):
		return errors.New("compaction request did not unwind after SIGKILL")
	}

	snapshotPath := filepath.Join(cfg.StateDir, "snapshot.json")
	snapshot, exists, err := readSnapshot(snapshotPath)
	if err != nil || !exists || snapshot.LastSequence == 0 {
		return fmt.Errorf("crash snapshot invalid: exists=%v sequence=%d err=%v", exists, snapshot.LastSequence, err)
	}
	scan, err := scanWAL(filepath.Join(cfg.StateDir, "events.wal"), snapshot.LastSequence)
	if err != nil {
		return fmt.Errorf("scan post-crash WAL: %w", err)
	}
	durableJobs, err := replayDurableState(snapshot, scan)
	if err != nil {
		return fmt.Errorf("replay post-crash durable state: %w", err)
	}
	if len(durableJobs) != len(records) {
		return fmt.Errorf("post-crash durable state contains %d jobs, expected %d", len(durableJobs), len(records))
	}
	for _, record := range records {
		durable, ok := durableJobs[record.id]
		if !ok || !sameDurableJob(durable, beforeKill[record.id]) {
			return fmt.Errorf("accepted job lost or changed at compaction crash: id=%s durable=%+v before=%+v ok=%v", record.id, durable, beforeKill[record.id], ok)
		}
	}

	address, err := reserveAddress()
	if err != nil {
		return err
	}
	cfg.Listen = address
	if err := writeJSON(configPath, cfg); err != nil {
		return err
	}
	restarted, err := startService(v.binDir, configPath, &cfg, filepath.Join(directory, "logs-two"))
	if err != nil {
		return fmt.Errorf("restart after compaction crash: %w", err)
	}
	defer restarted.kill()

	recoveryWriterResult := make(chan fifoOpenResult, 1)
	go func() {
		file, openErr := os.OpenFile(blockedFIFO, os.O_WRONLY, 0)
		recoveryWriterResult <- fifoOpenResult{path: blockedFIFO, file: file, openedAt: time.Now(), err: openErr}
	}()
	var recoveryWriter *os.File
	select {
	case opened := <-recoveryWriterResult:
		if opened.err != nil {
			return opened.err
		}
		recoveryWriter = opened.file
	case <-time.After(5 * time.Second):
		return errors.New("recovered running job never reopened its FIFO")
	}
	if _, err := recoveryWriter.Write(blockedPayload); err != nil {
		_ = recoveryWriter.Close()
		return err
	}
	if err := recoveryWriter.Close(); err != nil {
		return err
	}

	completed := make([]job, 0, len(records))
	for _, record := range records {
		value, terminalErr := waitTerminal(restarted, record.id, 15*time.Second)
		if terminalErr != nil {
			return fmt.Errorf("recover accepted request %s: %w", record.requestID, terminalErr)
		}
		if value.Status != "succeeded" || value.ID != record.id || value.Spec != record.spec ||
			value.Attempts != record.expectedAttempts || value.ArtifactSHA != record.artifactSHA || value.ArtifactSize != int64(len(record.artifact)) {
			return fmt.Errorf("recovered completion mismatch: record=%+v job=%+v", record, value)
		}
		observed, readErr := os.ReadFile(record.spec.Destination)
		if readErr != nil || !bytes.Equal(observed, record.artifact) {
			return fmt.Errorf("recovered artifact mismatch for %s: bytes=%d err=%v", record.requestID, len(observed), readErr)
		}
		listed, listErr := restarted.listByRequest(record.requestID)
		if listErr != nil || len(listed) != 1 || listed[0].ID != record.id || !sameDurableJob(listed[0], value) {
			return fmt.Errorf("recovered idempotency mapping changed for %s: jobs=%+v err=%v", record.requestID, listed, listErr)
		}
		duplicateStatus, duplicate, duplicateRaw, duplicateErr := restarted.submit(record.spec)
		if duplicateErr != nil || duplicateStatus != http.StatusOK || !duplicate.Existing || !sameDurableJob(duplicate.Job, value) {
			return fmt.Errorf("recovered duplicate %s status=%d result=%+v err=%v body=%s", record.requestID, duplicateStatus, duplicate, duplicateErr, strings.TrimSpace(string(duplicateRaw)))
		}
		completed = append(completed, value)
	}
	receiptPath := filepath.Join(cfg.StateDir, "receipts.jsonl")
	if err := assertExactReceipts(receiptPath, completed); err != nil {
		return fmt.Errorf("compaction-crash receipts: %w", err)
	}
	receipts, err := readReceipts(receiptPath)
	if err != nil {
		return err
	}
	if len(receipts) != len(records) {
		return fmt.Errorf("compaction-crash receipt count=%d expected=%d", len(receipts), len(records))
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
	svc, err := startService(v.binDir, configPath, &cfg, filepath.Join(directory, "logs-source"))
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
	if err := assertExactReceipts(filepath.Join(cfg.StateDir, "receipts.jsonl"), []job{completed, secondCompleted}); err != nil {
		return fmt.Errorf("corruption source completion receipts: %w", err)
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
		if err := prepareTestDirectory(caseDir); err != nil {
			return err
		}
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
		output, err := expectStartupFailure(v.binDir, caseConfigPath, &caseConfig, 1500*time.Millisecond)
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
