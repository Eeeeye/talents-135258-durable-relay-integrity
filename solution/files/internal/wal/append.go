package wal

import (
	"fmt"

	"example.com/durable-relay/internal/model"
)

func (w *Writer) AppendModel(event *model.Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return fmt.Errorf("WAL is closed")
	}
	event.Sequence = w.nextSequence
	header, payload, err := Encode(*event)
	if err != nil {
		return err
	}

	frame := make([]byte, 0, len(header)+len(payload))
	frame = append(frame, header...)
	frame = append(frame, payload...)
	if err := writeFull(w.file, frame); err != nil {
		return fmt.Errorf("write WAL frame: %w", err)
	}
	w.nextSequence++
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
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.nextSequence
}
