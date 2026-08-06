package wal

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

type Writer struct {
	mu           sync.Mutex
	path         string
	file         *os.File
	nextSequence uint64
	syncWrites   bool
	onAppend     func(int)
}

func OpenWriter(path string, nextSequence uint64, syncWrites bool, onAppend func(int)) (*Writer, error) {
	if nextSequence == 0 {
		nextSequence = 1
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open WAL %s: %w", path, err)
	}
	return &Writer{
		path:         path,
		file:         file,
		nextSequence: nextSequence,
		syncWrites:   syncWrites,
		onAppend:     onAppend,
	}, nil
}

func (w *Writer) Path() string {
	return w.path
}

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

func (w *Writer) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return errors.New("WAL is closed")
	}
	return w.file.Sync()
}

func (w *Writer) Truncate() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return errors.New("WAL is closed")
	}
	if err := w.file.Truncate(0); err != nil {
		return fmt.Errorf("truncate WAL: %w", err)
	}
	if _, err := w.file.Seek(0, 0); err != nil {
		return fmt.Errorf("seek WAL: %w", err)
	}
	if w.syncWrites {
		return w.file.Sync()
	}
	return nil
}

func writeFull(writer io.Writer, raw []byte) error {
	for len(raw) > 0 {
		written, err := writer.Write(raw)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		raw = raw[written:]
	}
	return nil
}
