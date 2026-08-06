package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
)

type Config struct {
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

func Default() Config {
	return Config{
		Listen:             "127.0.0.1:8787",
		StateDir:           "state",
		WorkerCount:        2,
		QueueCapacity:      4096,
		RetryBaseMS:        100,
		MaxAttempts:        3,
		SyncWAL:            true,
		MaxRequestBytes:    1 << 20,
		SnapshotIntervalMS: 0,
		ShutdownTimeoutMS:  5000,
	}
}

func LoadFile(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	cfg, err := Parse(raw)
	if err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	if !filepath.IsAbs(cfg.StateDir) {
		absolute, err := filepath.Abs(cfg.StateDir)
		if err != nil {
			return Config{}, fmt.Errorf("resolve state_dir: %w", err)
		}
		cfg.StateDir = absolute
	}
	return cfg, nil
}

func Parse(raw []byte) (Config, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	cfg := Default()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, err
	}
	if err := requireEOF(decoder); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("config contains multiple JSON values")
	}
	return err
}

func (c Config) Validate() error {
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("listen must be host:port: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("listen host must be an explicit loopback IP")
	}
	if port == "" || port == "0" {
		return errors.New("listen port must be nonzero")
	}
	if c.StateDir == "" {
		return errors.New("state_dir is required")
	}
	if c.WorkerCount < 1 || c.WorkerCount > 64 {
		return errors.New("worker_count must be between 1 and 64")
	}
	if c.QueueCapacity < 1 || c.QueueCapacity > 100000 {
		return errors.New("queue_capacity must be between 1 and 100000")
	}
	if c.RetryBaseMS < 1 || c.RetryBaseMS > 60000 {
		return errors.New("retry_base_ms must be between 1 and 60000")
	}
	if c.MaxAttempts < 1 || c.MaxAttempts > 20 {
		return errors.New("max_attempts must be between 1 and 20")
	}
	if c.MaxRequestBytes < 1024 || c.MaxRequestBytes > 16<<20 {
		return errors.New("max_request_bytes must be between 1024 and 16777216")
	}
	if c.SnapshotIntervalMS != 0 && c.SnapshotIntervalMS < 50 {
		return errors.New("snapshot_interval_ms must be zero or at least 50")
	}
	if c.SnapshotIntervalMS > 3600000 {
		return errors.New("snapshot_interval_ms must not exceed 3600000")
	}
	if c.ShutdownTimeoutMS < 100 || c.ShutdownTimeoutMS > 60000 {
		return errors.New("shutdown_timeout_ms must be between 100 and 60000")
	}
	return nil
}

func (c Config) ImmutableEqual(other Config) error {
	if c.Listen != other.Listen {
		return errors.New("listen cannot change during reload")
	}
	if c.StateDir != other.StateDir {
		return errors.New("state_dir cannot change during reload")
	}
	if c.QueueCapacity != other.QueueCapacity {
		return errors.New("queue_capacity cannot change during reload")
	}
	if c.SyncWAL != other.SyncWAL {
		return errors.New("sync_wal cannot change during reload")
	}
	if c.SnapshotIntervalMS != other.SnapshotIntervalMS {
		return errors.New("snapshot_interval_ms cannot change during reload")
	}
	if c.ShutdownTimeoutMS != other.ShutdownTimeoutMS {
		return errors.New("shutdown_timeout_ms cannot change during reload")
	}
	return nil
}
