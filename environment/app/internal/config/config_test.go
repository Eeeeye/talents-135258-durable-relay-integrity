package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseCompleteConfiguration(t *testing.T) {
	raw := []byte(`{
  "listen":"127.0.0.1:9123",
  "state_dir":"state",
  "worker_count":3,
  "queue_capacity":99,
  "retry_base_ms":17,
  "max_attempts":4,
  "sync_wal":false,
  "max_request_bytes":4096,
  "snapshot_interval_ms":250,
  "shutdown_timeout_ms":700
}`)
	cfg, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.Listen != "127.0.0.1:9123" || cfg.WorkerCount != 3 || cfg.SyncWAL {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestParseRejectsUnknownAndTrailingData(t *testing.T) {
	base := `{
  "listen":"127.0.0.1:9123",
  "state_dir":"state",
  "worker_count":3,
  "queue_capacity":99,
  "retry_base_ms":17,
  "max_attempts":4,
  "sync_wal":true,
  "max_request_bytes":4096,
  "snapshot_interval_ms":0,
  "shutdown_timeout_ms":700%s
}`
	for name, raw := range map[string]string{
		"unknown":  strings.ReplaceAll(base, "%s", `,"mystery":1`),
		"trailing": strings.ReplaceAll(base, "%s", ``) + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(raw)); err == nil {
				t.Fatal("Parse() unexpectedly succeeded")
			}
		})
	}
}

func TestValidateRequiresLoopbackAndBounds(t *testing.T) {
	valid := Default()
	cases := map[string]func(*Config){
		"wildcard-listen": func(cfg *Config) { cfg.Listen = "0.0.0.0:8787" },
		"zero-workers":    func(cfg *Config) { cfg.WorkerCount = 0 },
		"large-request":   func(cfg *Config) { cfg.MaxRequestBytes = 17 << 20 },
		"fast-snapshot":   func(cfg *Config) { cfg.SnapshotIntervalMS = 1 },
		"zero-attempts":   func(cfg *Config) { cfg.MaxAttempts = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := valid
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("Validate() accepted %+v", cfg)
			}
		})
	}
}

func TestManagerReloadIsAllOrNothingForInvalidFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "relay.json")
	initial := Default()
	initial.StateDir = filepath.Join(directory, "state")
	writeConfigForTest(t, path, initial)
	manager := NewManager(path, initial)

	next := initial
	next.WorkerCount = 7
	next.RetryBaseMS = 9
	writeConfigForTest(t, path, next)
	loaded, err := manager.Reload()
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if loaded.Generation != 2 || loaded.WorkerCount != 7 {
		t.Fatalf("unexpected reloaded snapshot: %+v", loaded)
	}

	if err := os.WriteFile(path, []byte(`{"listen":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Reload(); err == nil {
		t.Fatal("invalid reload unexpectedly succeeded")
	}
	current := manager.Current()
	if current.Generation != 2 || current.WorkerCount != 7 {
		t.Fatalf("failed reload changed current config: %+v", current)
	}
}

func writeConfigForTest(t *testing.T, path string, cfg Config) {
	t.Helper()
	raw := []byte(`{
"listen":"` + cfg.Listen + `",
"state_dir":"` + cfg.StateDir + `",
"worker_count":` + integer(cfg.WorkerCount) + `,
"queue_capacity":` + integer(cfg.QueueCapacity) + `,
"retry_base_ms":` + integer(cfg.RetryBaseMS) + `,
"max_attempts":` + integer(cfg.MaxAttempts) + `,
"sync_wal":true,
"max_request_bytes":` + integer64(cfg.MaxRequestBytes) + `,
"snapshot_interval_ms":` + integer(cfg.SnapshotIntervalMS) + `,
"shutdown_timeout_ms":` + integer(cfg.ShutdownTimeoutMS) + `
}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func integer(value int) string { return integer64(int64(value)) }

func integer64(value int64) string {
	if value == 0 {
		return "0"
	}
	negative := value < 0
	if negative {
		value = -value
	}
	var buffer [24]byte
	position := len(buffer)
	for value > 0 {
		position--
		buffer[position] = byte('0' + value%10)
		value /= 10
	}
	if negative {
		position--
		buffer[position] = '-'
	}
	return string(buffer[position:])
}
