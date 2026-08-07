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
	"regexp"
	"sort"
	"strconv"
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

var (
	activeCandidateUID uint32 = 60000
	activeCandidateGID uint32 = 60000
	managedPIDsMu      sync.Mutex
	managedPIDs        = make(map[int]struct{})
)

func setCandidateIdentity(index int) {
	// Stay within the 0..65535 range mapped by common rootless/user-namespace
	// runtimes while retaining a distinct otherwise-unused identity per case.
	activeCandidateUID = uint32(60000 + index)
	activeCandidateGID = activeCandidateUID
}

func candidateProcessAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGKILL,
		Credential: &syscall.Credential{
			Uid:         activeCandidateUID,
			Gid:         activeCandidateGID,
			NoSetGroups: true,
		},
	}
}

func signalProcessGroup(pid int, signal syscall.Signal) {
	if pid > 0 {
		_ = syscall.Kill(-pid, signal)
	}
}

func registerManagedPID(pid int) {
	managedPIDsMu.Lock()
	managedPIDs[pid] = struct{}{}
	managedPIDsMu.Unlock()
}

func unregisterManagedPID(pid int) {
	managedPIDsMu.Lock()
	delete(managedPIDs, pid)
	managedPIDsMu.Unlock()
}

func isManagedPID(pid int) bool {
	managedPIDsMu.Lock()
	_, ok := managedPIDs[pid]
	managedPIDsMu.Unlock()
	return ok
}

const prSetChildSubreaper = 36

func enableChildSubreaper() error {
	_, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, prSetChildSubreaper, 1, 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func directCandidateChildren(uid uint32) ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	parentPID := os.Getpid()
	var matches []int
	for _, entry := range entries {
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || pid <= 0 {
			continue
		}
		if isManagedPID(pid) {
			continue
		}
		raw, readErr := os.ReadFile(filepath.Join("/proc", entry.Name(), "status"))
		if errors.Is(readErr, os.ErrNotExist) {
			continue
		}
		if readErr != nil {
			return nil, readErr
		}
		processParent := -1
		var processUID uint64
		uidFound := false
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			switch fields[0] {
			case "PPid:":
				processParent, _ = strconv.Atoi(fields[1])
			case "Uid:":
				processUID, parseErr = strconv.ParseUint(fields[1], 10, 32)
				uidFound = parseErr == nil
			}
		}
		if processParent == parentPID && uidFound && uint32(processUID) == uid {
			matches = append(matches, pid)
		}
	}
	return matches, nil
}

func cleanupCandidateDescendants(uid uint32) error {
	// The verifier is a child subreaper. Once the directly managed command is
	// gone, even a double-forked or setsid(2) descendant is adopted here. Kill
	// only those children whose UID belongs to this scenario, then repeat as
	// deeper descendants are reparented. No system-wide UID sweep is used.
	for attempt := 0; attempt < 50; attempt++ {
		pids, err := directCandidateChildren(uid)
		if err != nil {
			return err
		}
		if len(pids) == 0 {
			return nil
		}
		for _, pid := range pids {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			_, _ = syscall.Wait4(pid, nil, syscall.WNOHANG, nil)
		}
		time.Sleep(5 * time.Millisecond)
	}
	pids, err := directCandidateChildren(uid)
	if err != nil {
		return err
	}
	return fmt.Errorf("candidate descendants survived cleanup: uid=%d pids=%v", uid, pids)
}

func prepareVerifierRoot(path string) error {
	if err := os.Chown(path, 0, 0); err != nil {
		return err
	}
	return os.Chmod(path, 0o711)
}

func prepareTestDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	if err := os.Chown(path, 0, int(activeCandidateGID)); err != nil {
		return err
	}
	// The candidate may create its state and destination subdirectories but
	// cannot list the verifier directory or remove root-owned inputs.
	return os.Chmod(path, os.ModeSticky|0o730)
}

func prepareCandidateReadableDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	if err := os.Chown(path, 0, int(activeCandidateGID)); err != nil {
		return err
	}
	return os.Chmod(path, 0o710)
}

func writeCandidateReadableFile(path string, raw []byte) error {
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return err
	}
	if err := os.Chown(path, 0, int(activeCandidateGID)); err != nil {
		return err
	}
	return os.Chmod(path, 0o640)
}

func prepareCandidateWritableDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	if err := os.Chown(path, int(activeCandidateUID), int(activeCandidateGID)); err != nil {
		return err
	}
	return os.Chmod(path, 0o700)
}

func prepareCandidateWritableTree(root string) error {
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := os.Chown(path, int(activeCandidateUID), int(activeCandidateGID)); err != nil {
			return err
		}
		if info.IsDir() {
			return os.Chmod(path, 0o700)
		}
		return os.Chmod(path, 0o600)
	})
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

func (v *verifier) intBetween(minimum, maximum int) int {
	if maximum < minimum {
		panic("invalid verifier integer range")
	}
	v.rngMu.Lock()
	value := minimum + v.rng.Intn(maximum-minimum+1)
	v.rngMu.Unlock()
	return value
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
	return writeCandidateReadableFile(path, raw)
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
	if err := prepareTestDirectory(directory); err != nil {
		return "", configFile{}, err
	}
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
	if err := prepareCandidateReadableDirectory(root); err != nil {
		return fixture{}, err
	}
	if err := prepareCandidateReadableDirectory(chunkDir); err != nil {
		return fixture{}, err
	}
	manifest := manifestFile{Version: 1}
	artifactHash := sha256.New()
	var artifact []byte
	result := fixture{Dir: root}
	for index, data := range chunks {
		name := filepath.Join("chunks with spaces", fmt.Sprintf("part %03d.bin", index))
		absolute := filepath.Join(root, name)
		if err := writeCandidateReadableFile(absolute, data); err != nil {
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
	if err := prepareCandidateReadableDirectory(root); err != nil {
		return fixture{}, "", err
	}
	fifoName := "blocking chunk.bin"
	fifoPath := filepath.Join(root, fifoName)
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		return fixture{}, "", err
	}
	if err := os.Chown(fifoPath, 0, int(activeCandidateGID)); err != nil {
		return fixture{}, "", err
	}
	if err := os.Chmod(fifoPath, 0o640); err != nil {
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
	addr         string
	cmd          *exec.Cmd
	done         chan error
	stderrPath   string
	candidateUID uint32
	mu           sync.Mutex
	finished     bool
	waitErr      error
}

func startService(binDir, configPath string, cfg *configFile, logDir string) (*service, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		svc, err := startServiceAttempt(binDir, configPath, cfg.Listen, cfg.StateDir, logDir)
		if err == nil {
			return svc, nil
		}
		lastErr = err
		if !strings.Contains(strings.ToLower(err.Error()), "address already in use") {
			return nil, err
		}
		address, reserveErr := reserveAddress()
		if reserveErr != nil {
			return nil, errors.Join(err, reserveErr)
		}
		cfg.Listen = address
		if writeErr := writeJSON(configPath, *cfg); writeErr != nil {
			return nil, errors.Join(err, writeErr)
		}
		time.Sleep(time.Duration(20*(attempt+1)) * time.Millisecond)
	}
	return nil, fmt.Errorf("relayqd startup exhausted address retries: %w", lastErr)
}

func startServiceAttempt(binDir, configPath, address, stateDir, logDir string) (*service, error) {
	if err := prepareCandidateWritableTree(stateDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chown(logDir, 0, 0); err != nil {
		return nil, err
	}
	if err := os.Chmod(logDir, 0o700); err != nil {
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
	cmd := exec.Command(filepath.Join(binDir, "relayqd"), "-config", configPath, "-log-level", "debug")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.SysProcAttr = candidateProcessAttributes()
	if err := cmd.Start(); err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		return nil, err
	}
	registerManagedPID(cmd.Process.Pid)
	svc := &service{
		addr: address, cmd: cmd, done: make(chan error, 1), stderrPath: stderrPath,
		candidateUID: activeCandidateUID,
	}
	go func() {
		err := cmd.Wait()
		unregisterManagedPID(cmd.Process.Pid)
		signalProcessGroup(cmd.Process.Pid, syscall.SIGKILL)
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

func runCLI(timeout time.Duration, path string, arguments ...string) (result []byte, resultErr error) {
	candidateUID := activeCandidateUID
	defer func() {
		resultErr = errors.Join(resultErr, cleanupCandidateDescendants(candidateUID))
	}()
	cmd := exec.Command(path, arguments...)
	cmd.SysProcAttr = candidateProcessAttributes()
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	registerManagedPID(cmd.Process.Pid)
	done := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		unregisterManagedPID(cmd.Process.Pid)
		done <- err
	}()
	var err error
	select {
	case err = <-done:
		signalProcessGroup(cmd.Process.Pid, syscall.SIGKILL)
	case <-time.After(timeout):
		signalProcessGroup(cmd.Process.Pid, syscall.SIGKILL)
		<-done
		return output.Bytes(), fmt.Errorf("command timed out: %s %s", path, strings.Join(arguments, " "))
	}
	if err != nil {
		return output.Bytes(), fmt.Errorf("command failed: %s %s: %w: %s", path, strings.Join(arguments, " "), err, strings.TrimSpace(output.String()))
	}
	return output.Bytes(), nil
}

func setProcessFileSizeLimit(pid int, limit uint64) error {
	// The verifier intentionally runs as root while relayqd runs under a fresh
	// unprivileged identity for every scenario. Docker's default capability set
	// does not let that root process use prlimit(2) across UIDs. Execute the
	// trusted util-linux helper as relayqd's own UID instead; same-UID prlimit is
	// permitted and the helper can affect only the explicitly named candidate
	// PID. The candidate cannot replace this root-owned binary.
	value := fmt.Sprintf("%d:%d", limit, limit)
	cmd := exec.Command("/usr/bin/prlimit", "--pid", fmt.Sprint(pid), "--fsize="+value)
	cmd.SysProcAttr = candidateProcessAttributes()
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("candidate-owned prlimit failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
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
		signalProcessGroup(s.cmd.Process.Pid, syscall.SIGKILL)
		return errors.Join(waitErr, cleanupCandidateDescendants(s.candidateUID))
	}
	signalProcessGroup(s.cmd.Process.Pid, syscall.SIGTERM)
	waitErr, err := s.await(5 * time.Second)
	if err != nil {
		signalProcessGroup(s.cmd.Process.Pid, syscall.SIGKILL)
		_, _ = s.await(2 * time.Second)
		return errors.Join(err, cleanupCandidateDescendants(s.candidateUID))
	}
	signalProcessGroup(s.cmd.Process.Pid, syscall.SIGKILL)
	return errors.Join(waitErr, cleanupCandidateDescendants(s.candidateUID))
}

func (s *service) kill() {
	signalProcessGroup(s.cmd.Process.Pid, syscall.SIGKILL)
	s.mu.Lock()
	finished := s.finished
	s.mu.Unlock()
	if !finished {
		_, _ = s.await(2 * time.Second)
	}
	_ = cleanupCandidateDescendants(s.candidateUID)
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

func assertExactReceipts(path string, expected []job) error {
	receipts, err := readReceipts(path)
	if err != nil {
		return err
	}
	for _, wanted := range expected {
		if wanted.Status != "succeeded" || wanted.CompletedAt.IsZero() {
			return fmt.Errorf("cannot require receipt for incomplete job: %+v", wanted)
		}
		matches := 0
		for _, observed := range receipts {
			if observed.JobID != wanted.ID && observed.RequestID != wanted.Spec.RequestID {
				continue
			}
			matches++
			if observed.Version != 1 || observed.JobID != wanted.ID ||
				observed.RequestID != wanted.Spec.RequestID || observed.Destination != wanted.Spec.Destination ||
				observed.ArtifactSize != wanted.ArtifactSize || observed.ArtifactSHA256 != wanted.ArtifactSHA ||
				!observed.CompletedAt.Equal(wanted.CompletedAt) {
				return fmt.Errorf("receipt differs from durable completion: receipt=%+v job=%+v", observed, wanted)
			}
		}
		if matches != 1 {
			return fmt.Errorf("job %q request %q has %d receipts, expected exactly one", wanted.ID, wanted.Spec.RequestID, matches)
		}
	}
	return nil
}

type durableSnapshot struct {
	Version      int            `json:"version"`
	LastSequence uint64         `json:"last_sequence"`
	CreatedAt    time.Time      `json:"created_at"`
	Jobs         map[string]job `json:"jobs"`
}

type durableEvent struct {
	Sequence uint64    `json:"sequence"`
	Type     string    `json:"type"`
	At       time.Time `json:"at"`
	Job      job       `json:"job"`
}

var durableRequestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func readSnapshot(path string) (durableSnapshot, bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return durableSnapshot{}, false, nil
	}
	if err != nil {
		return durableSnapshot{}, false, err
	}
	var value durableSnapshot
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return durableSnapshot{}, false, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return durableSnapshot{}, false, errors.New("snapshot has trailing JSON")
	}
	if value.Version != 1 || value.CreatedAt.IsZero() || value.Jobs == nil {
		return durableSnapshot{}, false, errors.New("snapshot required fields are invalid")
	}
	if len(value.Jobs) > 0 && value.LastSequence == 0 {
		return durableSnapshot{}, false, errors.New("nonempty snapshot has zero last_sequence")
	}
	requests := make(map[string]string, len(value.Jobs))
	for id, item := range value.Jobs {
		if id != item.ID {
			return durableSnapshot{}, false, fmt.Errorf("snapshot key %q differs from job id %q", id, item.ID)
		}
		if err := validateDurableJob(item); err != nil {
			return durableSnapshot{}, false, fmt.Errorf("snapshot job %q: %w", id, err)
		}
		if previous, exists := requests[item.Spec.RequestID]; exists && previous != id {
			return durableSnapshot{}, false, fmt.Errorf("snapshot request_id %q maps to jobs %q and %q", item.Spec.RequestID, previous, id)
		}
		requests[item.Spec.RequestID] = id
	}
	return value, true, nil
}

type walScan struct {
	Records      int
	LastSequence uint64
	Events       []durableEvent
}

type rawWALFrame struct {
	Header  []byte
	Payload []byte
}

func parseRawWALFrames(raw []byte) ([]rawWALFrame, error) {
	const headerSize = 24
	var frames []rawWALFrame
	for offset := 0; offset < len(raw); {
		if len(raw)-offset < headerSize {
			return nil, fmt.Errorf("partial raw header at %d", offset)
		}
		length := int(binary.LittleEndian.Uint32(raw[offset+8 : offset+12]))
		end := offset + headerSize + length
		if length <= 0 || end > len(raw) {
			return nil, fmt.Errorf("invalid raw frame length %d at %d", length, offset)
		}
		frames = append(frames, rawWALFrame{
			Header:  append([]byte(nil), raw[offset:offset+headerSize]...),
			Payload: append([]byte(nil), raw[offset+headerSize:end]...),
		})
		offset = end
	}
	return frames, nil
}

func encodeRawWALFrames(frames []rawWALFrame) []byte {
	var result []byte
	for _, frame := range frames {
		header := append([]byte(nil), frame.Header...)
		binary.LittleEndian.PutUint32(header[8:12], uint32(len(frame.Payload)))
		binary.LittleEndian.PutUint32(header[12:16], crc32.ChecksumIEEE(frame.Payload))
		result = append(result, header...)
		result = append(result, frame.Payload...)
	}
	return result
}

func cloneRawWALFrames(frames []rawWALFrame) []rawWALFrame {
	result := make([]rawWALFrame, len(frames))
	for index, frame := range frames {
		result[index] = rawWALFrame{
			Header:  append([]byte(nil), frame.Header...),
			Payload: append([]byte(nil), frame.Payload...),
		}
	}
	return result
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
		var event durableEvent
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&event); err != nil {
			return result, fmt.Errorf("event JSON at %d: %w", offset, err)
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			return result, fmt.Errorf("event trailing JSON at %d", offset)
		}
		if event.Sequence != sequence || event.At.IsZero() {
			return result, fmt.Errorf("event/header mismatch at %d", offset)
		}
		switch event.Type {
		case "job_submitted", "job_started", "job_retry", "job_succeeded", "job_failed":
		default:
			return result, fmt.Errorf("invalid event type %q at %d", event.Type, offset)
		}
		if err := validateDurableJob(event.Job); err != nil {
			return result, fmt.Errorf("invalid event job at %d: %w", offset, err)
		}
		result.Records++
		result.LastSequence = sequence
		result.Events = append(result.Events, event)
		expected++
		offset = end
	}
	return result, nil
}

func validateDurableJob(value job) error {
	if value.ID == "" {
		return errors.New("job id is empty")
	}
	if !durableRequestIDPattern.MatchString(value.Spec.RequestID) {
		return errors.New("request_id is invalid")
	}
	if value.Spec.Manifest == "" || value.Spec.Destination == "" || value.Spec.Manifest == value.Spec.Destination {
		return errors.New("job paths are invalid")
	}
	if value.Spec.MaxAttempts < 1 || value.Spec.MaxAttempts > 20 || value.Attempts < 0 || value.Attempts > value.Spec.MaxAttempts {
		return errors.New("attempt counts are invalid")
	}
	if value.CreatedAt.IsZero() || value.UpdatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) {
		return errors.New("job timestamps are invalid")
	}
	switch value.Status {
	case "pending":
		if value.Attempts != 0 || !value.CompletedAt.IsZero() {
			return errors.New("pending job has attempts or completion time")
		}
	case "running", "retry_wait":
		if value.Attempts < 1 || !value.CompletedAt.IsZero() {
			return errors.New("nonterminal attempted job is invalid")
		}
	case "succeeded":
		if value.Attempts < 1 || value.CompletedAt.IsZero() || value.ArtifactSize < 0 || len(value.ArtifactSHA) != 64 || value.ArtifactSHA != strings.ToLower(value.ArtifactSHA) {
			return errors.New("succeeded job completion fields are invalid")
		}
		if _, err := hex.DecodeString(value.ArtifactSHA); err != nil {
			return fmt.Errorf("succeeded job digest: %w", err)
		}
	case "failed":
		if value.Attempts < 1 || value.CompletedAt.IsZero() {
			return errors.New("failed job completion fields are invalid")
		}
	default:
		return fmt.Errorf("unknown status %q", value.Status)
	}
	return nil
}

func sameDurableJob(left, right job) bool {
	return left.ID == right.ID && left.Spec == right.Spec && left.Status == right.Status &&
		left.Attempts == right.Attempts && left.LastError == right.LastError &&
		left.ArtifactSize == right.ArtifactSize && left.ArtifactSHA == right.ArtifactSHA &&
		left.CreatedAt.Equal(right.CreatedAt) && left.UpdatedAt.Equal(right.UpdatedAt) &&
		left.CompletedAt.Equal(right.CompletedAt)
}

func replayDurableState(snapshot durableSnapshot, scan walScan) (map[string]job, error) {
	jobs := make(map[string]job, len(snapshot.Jobs)+len(scan.Events))
	requests := make(map[string]string, len(snapshot.Jobs)+len(scan.Events))
	for id, value := range snapshot.Jobs {
		jobs[id] = value
		requests[value.Spec.RequestID] = id
	}
	for _, event := range scan.Events {
		current := event.Job
		previous, exists := jobs[current.ID]
		if event.Type == "job_submitted" {
			if exists || current.Status != "pending" || current.Attempts != 0 || !current.CompletedAt.IsZero() {
				return nil, fmt.Errorf("invalid submitted event %d for job %q", event.Sequence, current.ID)
			}
			if existingID, duplicate := requests[current.Spec.RequestID]; duplicate && existingID != current.ID {
				return nil, fmt.Errorf("event %d duplicates request_id %q", event.Sequence, current.Spec.RequestID)
			}
			requests[current.Spec.RequestID] = current.ID
			jobs[current.ID] = current
			continue
		}
		if !exists {
			return nil, fmt.Errorf("event %d references unknown job %q", event.Sequence, current.ID)
		}
		if previous.Status == "succeeded" || previous.Status == "failed" {
			return nil, fmt.Errorf("event %d follows terminal job %q", event.Sequence, current.ID)
		}
		if previous.Spec != current.Spec || !previous.CreatedAt.Equal(current.CreatedAt) || current.UpdatedAt.Before(previous.UpdatedAt) {
			return nil, fmt.Errorf("event %d changes immutable or monotonic fields for job %q", event.Sequence, current.ID)
		}
		switch event.Type {
		case "job_started":
			if current.Status != "running" || current.Attempts != previous.Attempts+1 || !current.CompletedAt.IsZero() {
				return nil, fmt.Errorf("event %d has invalid started transition", event.Sequence)
			}
		case "job_retry":
			if previous.Status != "running" || current.Status != "retry_wait" || current.Attempts != previous.Attempts || !current.CompletedAt.IsZero() {
				return nil, fmt.Errorf("event %d has invalid retry transition", event.Sequence)
			}
		case "job_succeeded":
			if previous.Status != "running" || current.Status != "succeeded" || current.Attempts != previous.Attempts || current.CompletedAt.IsZero() {
				return nil, fmt.Errorf("event %d has invalid success transition", event.Sequence)
			}
		case "job_failed":
			if previous.Status != "running" || current.Status != "failed" || current.Attempts != previous.Attempts || current.CompletedAt.IsZero() {
				return nil, fmt.Errorf("event %d has invalid failure transition", event.Sequence)
			}
		default:
			return nil, fmt.Errorf("event %d has invalid type %q", event.Sequence, event.Type)
		}
		jobs[current.ID] = current
	}
	return jobs, nil
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
	if err := filepath.Walk(source, func(path string, info os.FileInfo, walkErr error) error {
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
	}); err != nil {
		return err
	}
	return prepareCandidateWritableTree(destination)
}

func expectStartupFailure(binDir, configPath string, cfg *configFile, timeout time.Duration) (string, error) {
	if err := prepareCandidateWritableTree(cfg.StateDir); err != nil {
		return "", err
	}
	for attempt := 0; attempt < 3; attempt++ {
		output, err := expectStartupFailureAttempt(binDir, configPath, cfg.Listen, timeout)
		if err != nil || !strings.Contains(strings.ToLower(output), "address already in use") {
			return output, err
		}
		address, reserveErr := reserveAddress()
		if reserveErr != nil {
			return output, reserveErr
		}
		cfg.Listen = address
		if writeErr := writeJSON(configPath, *cfg); writeErr != nil {
			return output, writeErr
		}
	}
	return "", errors.New("relayqd corrupt-state check exhausted address retries")
}

func expectStartupFailureAttempt(binDir, configPath, address string, timeout time.Duration) (string, error) {
	cmd := exec.Command(filepath.Join(binDir, "relayqd"), "-config", configPath, "-log-level", "error")
	cmd.SysProcAttr = candidateProcessAttributes()
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			signalProcessGroup(cmd.Process.Pid, syscall.SIGKILL)
			if err == nil {
				return combined.String(), errors.New("relayqd unexpectedly exited zero on corrupt state")
			}
			return combined.String(), nil
		default:
		}
		request, _ := http.NewRequest(http.MethodGet, "http://"+address+"/v1/health", nil)
		request.Close = true
		response, requestErr := (&http.Client{
			Timeout:   20 * time.Millisecond,
			Transport: &http.Transport{DisableKeepAlives: true},
		}).Do(request)
		if requestErr == nil {
			raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
			_ = response.Body.Close()
			var value health
			if response.StatusCode == http.StatusOK && json.Unmarshal(raw, &value) == nil && value.Ready {
				signalProcessGroup(cmd.Process.Pid, syscall.SIGKILL)
				<-done
				return combined.String(), errors.New("relayqd reported ready on corrupt state")
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	signalProcessGroup(cmd.Process.Pid, syscall.SIGKILL)
	<-done
	return combined.String(), errors.New("relayqd remained running on corrupt state")
}
