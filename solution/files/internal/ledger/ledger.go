package ledger

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"example.com/durable-relay/internal/model"
)

type Ledger struct {
	path string
	file *os.File
	mu   sync.Mutex
	seen map[string]model.Receipt
}

func Open(path string) (*Ledger, error) {
	existing, err := Scan(path)
	if err != nil {
		return nil, fmt.Errorf("scan receipt ledger: %w", err)
	}
	seen := make(map[string]model.Receipt, len(existing))
	for _, receipt := range existing {
		if previous, ok := seen[receipt.JobID]; ok {
			return nil, fmt.Errorf("duplicate receipts for job %q and request_id %q", previous.JobID, receipt.RequestID)
		}
		seen[receipt.JobID] = receipt
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open receipt ledger: %w", err)
	}
	return &Ledger{path: path, file: file, seen: seen}, nil
}

func (l *Ledger) Path() string {
	return l.path
}

func (l *Ledger) Append(receipt model.Receipt) error {
	raw, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return errors.New("receipt ledger is closed")
	}
	if previous, ok := l.seen[receipt.JobID]; ok {
		if sameReceipt(previous, receipt) {
			return nil
		}
		return fmt.Errorf("receipt conflict for job %q and request_id %q", receipt.JobID, receipt.RequestID)
	}
	if _, err := l.file.Write(raw); err != nil {
		return fmt.Errorf("append receipt: %w", err)
	}
	if err := l.file.Sync(); err != nil {
		return fmt.Errorf("sync receipt: %w", err)
	}
	l.seen[receipt.JobID] = receipt
	return nil
}

func sameReceipt(left, right model.Receipt) bool {
	return left.Version == right.Version &&
		left.JobID == right.JobID &&
		left.RequestID == right.RequestID &&
		left.Destination == right.Destination &&
		left.ArtifactSize == right.ArtifactSize &&
		left.ArtifactSHA256 == right.ArtifactSHA256 &&
		left.CompletedAt.Equal(right.CompletedAt)
}

func (l *Ledger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

func Scan(path string) ([]model.Receipt, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var receipts []model.Receipt
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	line := 0
	for scanner.Scan() {
		line++
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			return nil, fmt.Errorf("receipt line %d is empty", line)
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		var receipt model.Receipt
		if err := decoder.Decode(&receipt); err != nil {
			return nil, fmt.Errorf("decode receipt line %d: %w", line, err)
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("receipt line %d has trailing JSON", line)
		}
		if receipt.Version != 1 || receipt.JobID == "" || receipt.RequestID == "" {
			return nil, fmt.Errorf("receipt line %d has invalid required fields", line)
		}
		receipts = append(receipts, receipt)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return receipts, nil
}
