package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

type verifier struct {
	binDir string
	root   string
	seed   int64
	rng    *rand.Rand
	rngMu  sync.Mutex
}

type configFile struct {
	Listen             string `json:"listen"`
	StateDir           string `json:"state_dir"`
	WorkerCount        int    `json:"worker_count"`
	QueueCapacity      int    `json:"queue_capacity"`
	RetryBaseMS        int    `json:"retry_base_ms"`
	MaxAttempts        int    `json:"max_attempts"`
	SyncWAL            bool   `json:"sync_wal"`
	MaxRequestBytes    int64  `json:"max_request_bytes"`
	SnapshotIntervalMS int    `json:"snapshot_interval_ms"`
	ShutdownTimeoutMS  int    `json:"shutdown_timeout_ms"`
}

func baseConfig() configFile {
	return configFile{
		WorkerCount:        2,
		QueueCapacity:      4096,
		RetryBaseMS:        40,
		MaxAttempts:        3,
		SyncWAL:            true,
		MaxRequestBytes:    1 << 20,
		SnapshotIntervalMS: 0,
		ShutdownTimeoutMS:  5000,
	}
}

type manifestChunk struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type manifestFile struct {
	Version        int             `json:"version"`
	ArtifactSize   int64           `json:"artifact_size"`
	ArtifactSHA256 string          `json:"artifact_sha256"`
	Chunks         []manifestChunk `json:"chunks"`
}

type fixture struct {
	Dir          string
	Manifest     string
	ChunkPaths   []string
	ChunkData    [][]byte
	Artifact     []byte
	ArtifactSHA  string
	ArtifactSize int64
}

type jobSpec struct {
	RequestID   string `json:"request_id"`
	Manifest    string `json:"manifest"`
	Destination string `json:"destination"`
	MaxAttempts int    `json:"max_attempts,omitempty"`
}

type job struct {
	ID           string    `json:"id"`
	Spec         jobSpec   `json:"spec"`
	Status       string    `json:"status"`
	Attempts     int       `json:"attempts"`
	LastError    string    `json:"last_error,omitempty"`
	ArtifactSize int64     `json:"artifact_size,omitempty"`
	ArtifactSHA  string    `json:"artifact_sha256,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	CompletedAt  time.Time `json:"completed_at,omitempty"`
}

type submitResult struct {
	Job      job  `json:"job"`
	Existing bool `json:"existing"`
}

type jobList struct {
	Jobs []job `json:"jobs"`
}

type health struct {
	Ready            bool     `json:"ready"`
	ConfigGeneration uint64   `json:"config_generation"`
	RecoveredJobs    int      `json:"recovered_jobs"`
	RecoveryWarnings []string `json:"recovery_warnings,omitempty"`
}

type configSnapshot struct {
	Generation uint64 `json:"generation"`
	configFile
}

type runtimeStats struct {
	Accepted          uint64 `json:"accepted"`
	Deduplicated      uint64 `json:"deduplicated"`
	Started           uint64 `json:"started"`
	Retried           uint64 `json:"retried"`
	Succeeded         uint64 `json:"succeeded"`
	Failed            uint64 `json:"failed"`
	WALAppends        uint64 `json:"wal_appends"`
	WALBytes          uint64 `json:"wal_bytes"`
	Snapshots         uint64 `json:"snapshots"`
	RecoveryWarnings  uint64 `json:"recovery_warnings"`
	ActiveWorkers     int64  `json:"active_workers"`
	ActiveWorkerLimit int64  `json:"active_worker_limit"`
	QueueDepth        int64  `json:"queue_depth"`
}

type stats struct {
	Config           configSnapshot `json:"config"`
	Runtime          runtimeStats   `json:"runtime"`
	LastSequence     uint64         `json:"last_sequence"`
	RecoveryWarnings []string       `json:"recovery_warnings,omitempty"`
}

type errorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type receipt struct {
	Version        int       `json:"version"`
	JobID          string    `json:"job_id"`
	RequestID      string    `json:"request_id"`
	Destination    string    `json:"destination"`
	ArtifactSize   int64     `json:"artifact_size"`
	ArtifactSHA256 string    `json:"artifact_sha256"`
	CompletedAt    time.Time `json:"completed_at"`
}

func (v *verifier) token(prefix string) string {
	v.rngMu.Lock()
	value := v.rng.Uint64()
	v.rngMu.Unlock()
	return fmt.Sprintf("%s-%016x", prefix, value)
}

func (v *verifier) bytes(size int) []byte {
	raw := make([]byte, size)
	v.rngMu.Lock()
	_, _ = v.rng.Read(raw)
	v.rngMu.Unlock()
	return raw
}

func writeJSON(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func reserveAddress() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		return "", err
	}
	return address, nil
}

func (v *verifier) prepareConfig(directory string, cfg configFile) (string, configFile, error) {
	address, err := reserveAddress()
	if err != nil {
		return "", configFile{}, err
	}
	cfg.Listen = address
	if cfg.StateDir == "" {
		cfg.StateDir = filepath.Join(directory, "state")
	}
	path := filepath.Join(directory, "relay.json")
	if err := writeJSON(path, cfg); err != nil {
		return "", configFile{}, err
	}
	return path, cfg, nil
}

func (v *verifier) makeFixture(directory, label string, chunks [][]byte) (fixture, error) {
	root := filepath.Join(directory, label)
	chunkDir := filepath.Join(root, "chunks with spaces")
	if err := os.MkdirAll(chunkDir, 0o700); err != nil {
		return fixture{}, err
	}
	manifest := manifestFile{Version: 1}
	artifactHash := sha256.New()
	var artifact []byte
	result := fixture{Dir: root}
	for index, data := range chunks {
		name := filepath.Join("chunks with spaces", fmt.Sprintf("part %03d.bin", index))
		absolute := filepath.Join(root, name)
		if err := os.WriteFile(absolute, data, 0o600); err != nil {
			return fixture{}, err
		}
		digest := sha256.Sum256(data)
		manifest.Chunks = append(manifest.Chunks, manifestChunk{
			Path: name, Size: int64(len(data)), SHA256: hex.EncodeToString(digest[:]),
		})
		manifest.ArtifactSize += int64(len(data))
		_, _ = artifactHash.Write(data)
		artifact = append(artifact, data...)
		result.ChunkPaths = append(result.ChunkPaths, absolute)
		result.ChunkData = append(result.ChunkData, append([]byte(nil), data...))
	}
	manifest.ArtifactSHA256 = hex.EncodeToString(artifactHash.Sum(nil))
	manifestPath := filepath.Join(root, "manifest.json")
	if err := writeJSON(manifestPath, manifest); err != nil {
		return fixture{}, err
	}
	result.Manifest = manifestPath
	result.Artifact = artifact
	result.ArtifactSHA = manifest.ArtifactSHA256
	result.ArtifactSize = manifest.ArtifactSize
	return result, nil
}

func (v *verifier) makeFIFOFixture(directory, label string, payload []byte) (fixture, string, error) {
	root := filepath.Join(directory, label)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fixture{}, "", err
	}
	fifoName := "blocking chunk.bin"
	fifoPath := filepath.Join(root, fifoName)
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		return fixture{}, "", err
	}
	digest := sha256.Sum256(payload)
	manifest := manifestFile{
		Version:        1,
		ArtifactSize:   int64(len(payload)),
		ArtifactSHA256: hex.EncodeToString(digest[:]),
		Chunks: []manifestChunk{{
			Path: fifoName, Size: int64(len(payload)), SHA256: hex.EncodeToString(digest[:]),
		}},
	}
	manifestPath := filepath.Join(root, "manifest.json")
	if err := writeJSON(manifestPath, manifest); err != nil {
		return fixture{}, "", err
	}
	return fixture{
		Dir: root, Manifest: manifestPath, ChunkPaths: []string{fifoPath},
		ChunkData: [][]byte{payload}, Artifact: append([]byte(nil), payload...),
		ArtifactSHA: manifest.ArtifactSHA256, ArtifactSize: int64(len(payload)),
	}, fifoPath, nil
}

type service struct {
	addr       string
	cmd        *exec.Cmd
	done       chan error
	stderrPath string
	mu         sync.Mutex
	finished   bool
	waitErr    error
}

func startService(binDir, configPath, address, logDir string) (*service, error) {
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return nil, err
	}
	stdoutPath := filepath.Join(logDir, "relayqd.stdout.log")
	stderrPath := filepath.Join(logDir, "relayqd.stderr.log")
	stdout, err := os.Create(stdoutPath)
	if err != nil {
		return nil, err
	}
	stderr, err := os.Create(stderrPath)
	if err != nil {
		_ = stdout.Close()
		return nil, err
	}
	cmd := exec.Command(filepath.Join(binDir, "relayqd"), "-config", configPath)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		return nil, err
	}
	svc := &service{addr: address, cmd: cmd, done: make(chan error, 1), stderrPath: stderrPath}
	go func() {
		err := cmd.Wait()
		_ = stdout.Close()
		_ = stderr.Close()
		svc.done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case waitErr := <-svc.done:
			svc.markFinished(waitErr)
			raw, _ := os.ReadFile(stderrPath)
			return nil, fmt.Errorf("relayqd exited during startup: %v: %s", waitErr, strings.TrimSpace(string(raw)))
		default:
		}
		request, _ := http.NewRequest(http.MethodGet, "http://"+address+"/v1/health", nil)
		request.Close = true
		response, requestErr := (&http.Client{
			Timeout:   150 * time.Millisecond,
			Transport: &http.Transport{DisableKeepAlives: true},
		}).Do(request)
		if requestErr == nil {
			raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
			_ = response.Body.Close()
			var value health
			if response.StatusCode == http.StatusOK && json.Unmarshal(raw, &value) == nil && value.Ready {
				return svc, nil
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	svc.kill()
	raw, _ := os.ReadFile(stderrPath)
	return nil, fmt.Errorf("relayqd did not become ready: %s", strings.TrimSpace(string(raw)))
}

func (s *service) markFinished(err error) {
	s.mu.Lock()
	s.finished = true
	s.waitErr = err
	s.mu.Unlock()
}

func (s *service) await(timeout time.Duration) (error, error) {
	s.mu.Lock()
	if s.finished {
		waitErr := s.waitErr
		s.mu.Unlock()
		return waitErr, nil
	}
	s.mu.Unlock()
	select {
	case waitErr := <-s.done:
		s.markFinished(waitErr)
		return waitErr, nil
	case <-time.After(timeout):
		return nil, errors.New("timeout waiting for relayqd")
	}
}

func (s *service) stop() error {
	s.mu.Lock()
	finished := s.finished
	s.mu.Unlock()
	if finished {
		waitErr, _ := s.await(0)
		return waitErr
	}
	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	waitErr, err := s.await(5 * time.Second)
	if err != nil {
		_ = s.cmd.Process.Kill()
		_, _ = s.await(2 * time.Second)
		return err
	}
	return waitErr
}

func (s *service) kill() {
	s.mu.Lock()
	finished := s.finished
	s.mu.Unlock()
	if finished {
		return
	}
	_ = s.cmd.Process.Kill()
	_, _ = s.await(2 * time.Second)
}

func (s *service) requestRaw(method, path, contentType string, body []byte) (int, []byte, error) {
	request, err := http.NewRequest(method, "http://"+s.addr+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	request.Close = true
	response, err := (&http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}).Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	return response.StatusCode, raw, err
}

func (s *service) requestJSON(method, path string, body any) (int, []byte, error) {
	if body == nil {
		return s.requestRaw(method, path, "", nil)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	return s.requestRaw(method, path, "application/json", raw)
}

func (s *service) submit(spec jobSpec) (int, submitResult, []byte, error) {
	status, raw, err := s.requestJSON(http.MethodPost, "/v1/jobs", spec)
	if err != nil {
		return 0, submitResult{}, raw, err
	}
	var result submitResult
	if status == http.StatusAccepted || status == http.StatusOK {
		if err := json.Unmarshal(raw, &result); err != nil {
			return status, submitResult{}, raw, err
		}
	}
	return status, result, raw, nil
}

func (s *service) getJob(id string) (job, error) {
	status, raw, err := s.requestJSON(http.MethodGet, "/v1/jobs/"+url.PathEscape(id), nil)
	if err != nil {
		return job{}, err
	}
	if status != http.StatusOK {
		return job{}, fmt.Errorf("GET job status %d: %s", status, strings.TrimSpace(string(raw)))
	}
	var result job
	if err := json.Unmarshal(raw, &result); err != nil {
		return job{}, err
	}
	return result, nil
}

func (s *service) listByRequest(requestID string) ([]job, error) {
	status, raw, err := s.requestJSON(http.MethodGet, "/v1/jobs?request_id="+url.QueryEscape(requestID), nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("list status %d: %s", status, strings.TrimSpace(string(raw)))
	}
	var result jobList
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return result.Jobs, nil
}

func (s *service) readStats() (stats, error) {
	status, raw, err := s.requestJSON(http.MethodGet, "/v1/stats", nil)
	if err != nil {
		return stats{}, err
	}
	if status != http.StatusOK {
		return stats{}, fmt.Errorf("stats status %d: %s", status, strings.TrimSpace(string(raw)))
	}
	var result stats
	if err := json.Unmarshal(raw, &result); err != nil {
		return stats{}, err
	}
	return result, nil
}

func waitForJob(s *service, id string, timeout time.Duration, predicate func(job) bool) (job, error) {
	deadline := time.Now().Add(timeout)
	var last job
	for time.Now().Before(deadline) {
		current, err := s.getJob(id)
		if err == nil {
			last = current
			if predicate(current) {
				return current, nil
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return last, fmt.Errorf("job %s did not reach requested state, last=%+v", id, last)
}

func waitTerminal(s *service, id string, timeout time.Duration) (job, error) {
	return waitForJob(s, id, timeout, func(value job) bool {
		return value.Status == "succeeded" || value.Status == "failed"
	})
}

func readReceipts(path string) ([]receipt, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var result []receipt
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	line := 0
	for scanner.Scan() {
		line++
		raw := append([]byte(nil), scanner.Bytes()...)
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		var value receipt
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("receipt line %d: %w", line, err)
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("receipt line %d has trailing JSON", line)
		}
		if value.Version != 1 || value.JobID == "" || value.RequestID == "" || value.CompletedAt.IsZero() {
			return nil, fmt.Errorf("receipt line %d has invalid required fields", line)
		}
		result = append(result, value)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func readSnapshotLast(path string) (uint64, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var value struct {
		Version      int             `json:"version"`
		LastSequence uint64          `json:"last_sequence"`
		CreatedAt    time.Time       `json:"created_at"`
		Jobs         json.RawMessage `json:"jobs"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return 0, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return 0, errors.New("snapshot has trailing JSON")
	}
	if value.Version != 1 || value.CreatedAt.IsZero() || len(value.Jobs) == 0 {
		return 0, errors.New("snapshot required fields are invalid")
	}
	return value.LastSequence, nil
}

type walScan struct {
	Records      int
	LastSequence uint64
}

func scanWAL(path string, snapshotLast uint64) (walScan, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return walScan{LastSequence: snapshotLast}, nil
	}
	if err != nil {
		return walScan{}, err
	}
	const headerSize = 24
	const maximumPayload = 4 << 20
	offset := 0
	expected := snapshotLast + 1
	result := walScan{LastSequence: snapshotLast}
	for offset < len(raw) {
		if len(raw)-offset < headerSize {
			return result, fmt.Errorf("truncated header at %d", offset)
		}
		header := raw[offset : offset+headerSize]
		if string(header[0:4]) != "DRW1" {
			return result, fmt.Errorf("invalid magic at %d", offset)
		}
		if binary.LittleEndian.Uint16(header[4:6]) != 1 || binary.LittleEndian.Uint16(header[6:8]) != 0 {
			return result, fmt.Errorf("invalid version/flags at %d", offset)
		}
		length := binary.LittleEndian.Uint32(header[8:12])
		checksum := binary.LittleEndian.Uint32(header[12:16])
		sequence := binary.LittleEndian.Uint64(header[16:24])
		if length == 0 || length > maximumPayload {
			return result, fmt.Errorf("invalid payload length %d at %d", length, offset)
		}
		if sequence != expected {
			return result, fmt.Errorf("sequence %d at %d, expected %d", sequence, offset, expected)
		}
		end := offset + headerSize + int(length)
		if end > len(raw) {
			return result, fmt.Errorf("truncated payload at %d", offset)
		}
		payload := raw[offset+headerSize : end]
		if crc32.ChecksumIEEE(payload) != checksum {
			return result, fmt.Errorf("checksum mismatch at %d", offset)
		}
		var event struct {
			Sequence uint64          `json:"sequence"`
			Type     string          `json:"type"`
			At       time.Time       `json:"at"`
			Job      json.RawMessage `json:"job"`
		}
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&event); err != nil {
			return result, fmt.Errorf("event JSON at %d: %w", offset, err)
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			return result, fmt.Errorf("event trailing JSON at %d", offset)
		}
		if event.Sequence != sequence || event.At.IsZero() || len(event.Job) == 0 {
			return result, fmt.Errorf("event/header mismatch at %d", offset)
		}
		switch event.Type {
		case "job_submitted", "job_started", "job_retry", "job_succeeded", "job_failed":
		default:
			return result, fmt.Errorf("invalid event type %q at %d", event.Type, offset)
		}
		result.Records++
		result.LastSequence = sequence
		expected++
		offset = end
	}
	return result, nil
}

func directoryNames(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

func copyTree(source, destination string) error {
	return filepath.Walk(source, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("unexpected symlink in state: %s", path)
		}
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		defer input.Close()
		output, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(output, input)
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
}

func fileDigest(path string) (string, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), raw, nil
}

func expectStartupFailure(binDir, configPath string, timeout time.Duration) (string, error) {
	cmd := exec.Command(filepath.Join(binDir, "relayqd"), "-config", configPath)
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			return combined.String(), errors.New("relayqd unexpectedly exited zero on corrupt state")
		}
		return combined.String(), nil
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done
		return combined.String(), errors.New("relayqd remained running on corrupt state")
	}
}
