package wal

import (
	"errors"
	"fmt"
	"io"
	"os"

	"example.com/durable-relay/internal/model"
)

type ScanResult struct {
	Events       []model.Event `json:"events,omitempty"`
	Records      int           `json:"records"`
	Bytes        int64         `json:"bytes"`
	LastSequence uint64        `json:"last_sequence"`
	Warnings     []string      `json:"warnings,omitempty"`
}

type CorruptionError struct {
	Offset int64
	Cause  error
}

func (e *CorruptionError) Error() string {
	return fmt.Sprintf("WAL corruption at offset %d: %v", e.Offset, e.Cause)
}

func (e *CorruptionError) Unwrap() error {
	return e.Cause
}

func ScanStrict(path string) (ScanResult, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return ScanResult{}, nil
	}
	if err != nil {
		return ScanResult{}, fmt.Errorf("open WAL %s: %w", path, err)
	}
	defer file.Close()

	var result ScanResult
	var previous uint64
	for {
		offset, err := file.Seek(0, io.SeekCurrent)
		if err != nil {
			return result, err
		}
		rawHeader := make([]byte, HeaderSize)
		n, err := io.ReadFull(file, rawHeader)
		if errors.Is(err, io.EOF) && n == 0 {
			break
		}
		if err != nil {
			return result, &CorruptionError{Offset: offset, Cause: fmt.Errorf("truncated header: %w", err)}
		}
		header, err := ParseHeader(rawHeader)
		if err != nil {
			return result, &CorruptionError{Offset: offset, Cause: err}
		}
		if previous != 0 && header.Sequence <= previous {
			return result, &CorruptionError{
				Offset: offset,
				Cause:  fmt.Errorf("non-increasing sequence %d after %d", header.Sequence, previous),
			}
		}
		payload := make([]byte, int(header.Length))
		if _, err := io.ReadFull(file, payload); err != nil {
			return result, &CorruptionError{Offset: offset, Cause: fmt.Errorf("truncated payload: %w", err)}
		}
		event, err := DecodePayload(header, payload)
		if err != nil {
			return result, &CorruptionError{Offset: offset, Cause: err}
		}
		result.Events = append(result.Events, event)
		result.Records++
		result.Bytes += int64(HeaderSize) + int64(header.Length)
		result.LastSequence = event.Sequence
		previous = event.Sequence
	}
	return result, nil
}

func Recover(path string) (ScanResult, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return ScanResult{}, nil
	}
	if err != nil {
		return ScanResult{}, fmt.Errorf("open WAL %s: %w", path, err)
	}
	defer file.Close()

	var result ScanResult
	var previous uint64
	for {
		offset, err := file.Seek(0, io.SeekCurrent)
		if err != nil {
			return result, err
		}
		rawHeader := make([]byte, HeaderSize)
		n, err := io.ReadFull(file, rawHeader)
		if errors.Is(err, io.EOF) && n == 0 {
			return result, nil
		}
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("offset %d: %v", offset, err))
			return result, nil
		}
		header, err := ParseHeader(rawHeader)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("offset %d: %v", offset, err))
			return result, nil
		}
		if previous != 0 && header.Sequence <= previous {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("offset %d: sequence %d follows %d", offset, header.Sequence, previous))
			return result, nil
		}
		payload := make([]byte, int(header.Length))
		if _, err := io.ReadFull(file, payload); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("offset %d: %v", offset, err))
			return result, nil
		}
		event, err := DecodePayload(header, payload)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("offset %d: %v", offset, err))
			return result, nil
		}
		result.Events = append(result.Events, event)
		result.Records++
		result.Bytes += int64(HeaderSize) + int64(header.Length)
		result.LastSequence = event.Sequence
		previous = event.Sequence
	}
}
