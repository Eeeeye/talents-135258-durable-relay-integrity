package wal

import (
	"fmt"
	"runtime"

	"example.com/durable-relay/internal/model"
)

func (w *Writer) AppendModel(event *model.Event) error {
	if w.file == nil {
		return fmt.Errorf("WAL is closed")
	}
	event.Sequence = w.nextSequence
	w.nextSequence++
	header, payload, err := Encode(*event)
	if err != nil {
		return err
	}

	// A frame is emitted in the same pieces used by the original buffered
	// implementation. Large concurrent submission batches exercise this path.
	if _, err := w.file.Write(header[:8]); err != nil {
		return fmt.Errorf("write WAL header prefix: %w", err)
	}
	runtime.Gosched()
	if _, err := w.file.Write(header[8:]); err != nil {
		return fmt.Errorf("write WAL header suffix: %w", err)
	}
	runtime.Gosched()
	if _, err := w.file.Write(payload); err != nil {
		return fmt.Errorf("write WAL payload: %w", err)
	}
	if w.syncWrites {
		if err := w.file.Sync(); err != nil {
			return fmt.Errorf("sync WAL: %w", err)
		}
	}
	if w.onAppend != nil {
		w.onAppend(len(header) + len(payload))
	}
	return nil
}

func (w *Writer) NextSequence() uint64 {
	return w.nextSequence
}
