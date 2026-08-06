package snapshot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

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
	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open snapshot: %w", err)
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
	return nil
}
