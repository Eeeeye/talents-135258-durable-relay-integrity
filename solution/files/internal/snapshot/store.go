package snapshot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"example.com/durable-relay/internal/model"
)

type Store struct {
	path string
}

func New(path string) *Store {
	return &Store{path: path}
}

func (s *Store) Path() string {
	return s.path
}

func (s *Store) Load() (model.Snapshot, bool, error) {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return model.Snapshot{}, false, nil
	}
	if err != nil {
		return model.Snapshot{}, false, fmt.Errorf("read snapshot: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var snapshot model.Snapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return model.Snapshot{}, false, fmt.Errorf("decode snapshot: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return model.Snapshot{}, false, errors.New("snapshot has multiple JSON values")
		}
		return model.Snapshot{}, false, fmt.Errorf("decode snapshot trailing data: %w", err)
	}
	if err := snapshot.Validate(); err != nil {
		return model.Snapshot{}, false, fmt.Errorf("validate snapshot: %w", err)
	}
	return snapshot, true, nil
}

func (s *Store) Save(snapshot model.Snapshot) error {
	if err := snapshot.Validate(); err != nil {
		return err
	}
	directory := filepath.Dir(s.path)
	file, err := os.CreateTemp(directory, "."+filepath.Base(s.path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("open snapshot: %w", err)
	}
	temporary := file.Name()
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("protect snapshot temporary: %w", err)
	}
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(snapshot); err != nil {
		file.Close()
		return fmt.Errorf("encode snapshot: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync snapshot: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close snapshot: %w", err)
	}
	if err := os.Rename(temporary, s.path); err != nil {
		return fmt.Errorf("replace snapshot: %w", err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open snapshot directory: %w", err)
	}
	if err := directoryHandle.Sync(); err != nil {
		directoryHandle.Close()
		return fmt.Errorf("sync snapshot directory: %w", err)
	}
	if err := directoryHandle.Close(); err != nil {
		return fmt.Errorf("close snapshot directory: %w", err)
	}
	keep = true
	return nil
}
