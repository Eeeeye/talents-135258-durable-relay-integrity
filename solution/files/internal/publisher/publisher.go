package publisher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type Result struct {
	Size   int64
	SHA256 string
}

type Publisher struct {
	bufferSize int
}

func New() *Publisher {
	return &Publisher{bufferSize: 128 << 10}
}

func (p *Publisher) Publish(ctx context.Context, manifestPath, destination string) (Result, error) {
	manifest, manifestDir, err := LoadManifest(manifestPath)
	if err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
		return Result{}, fmt.Errorf("create destination directory: %w", err)
	}
	destinationDirectory := filepath.Dir(destination)
	output, err := os.CreateTemp(destinationDirectory, "."+filepath.Base(destination)+".tmp-*")
	if err != nil {
		return Result{}, fmt.Errorf("open publication temporary: %w", err)
	}
	temporary := output.Name()
	closed := false
	published := false
	defer func() {
		if !closed {
			_ = output.Close()
		}
		if !published {
			_ = os.Remove(temporary)
		}
	}()
	if err := output.Chmod(0o640); err != nil {
		return Result{}, fmt.Errorf("protect publication temporary: %w", err)
	}

	artifactHash := sha256.New()
	combined := io.MultiWriter(output, artifactHash)
	buffer := make([]byte, p.bufferSize)
	var written int64
	for index, chunk := range manifest.Chunks {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		chunkPath := filepath.Join(manifestDir, chunk.Path)
		count, digest, err := copyChunk(ctx, combined, chunkPath, buffer)
		if err != nil {
			return Result{}, fmt.Errorf("chunk %d %q: %w", index, chunk.Path, err)
		}
		if count != chunk.Size {
			return Result{}, fmt.Errorf("chunk %d size %d, expected %d", index, count, chunk.Size)
		}
		if digest != chunk.SHA256 {
			return Result{}, fmt.Errorf("chunk %d sha256 %s, expected %s", index, digest, chunk.SHA256)
		}
		written += count
	}
	observedArtifact := hex.EncodeToString(artifactHash.Sum(nil))
	if written != manifest.ArtifactSize {
		return Result{}, fmt.Errorf("artifact size %d, expected %d", written, manifest.ArtifactSize)
	}
	if observedArtifact != manifest.ArtifactSHA256 {
		return Result{}, fmt.Errorf("artifact sha256 %s, expected %s", observedArtifact, manifest.ArtifactSHA256)
	}
	if err := output.Sync(); err != nil {
		return Result{}, fmt.Errorf("sync destination: %w", err)
	}
	if err := output.Close(); err != nil {
		return Result{}, fmt.Errorf("close publication temporary: %w", err)
	}
	closed = true
	if err := os.Rename(temporary, destination); err != nil {
		return Result{}, fmt.Errorf("replace destination: %w", err)
	}
	published = true
	directoryHandle, err := os.Open(destinationDirectory)
	if err != nil {
		return Result{}, fmt.Errorf("open destination directory: %w", err)
	}
	if err := directoryHandle.Sync(); err != nil {
		directoryHandle.Close()
		return Result{}, fmt.Errorf("sync destination directory: %w", err)
	}
	if err := directoryHandle.Close(); err != nil {
		return Result{}, fmt.Errorf("close destination directory: %w", err)
	}
	return Result{Size: written, SHA256: observedArtifact}, nil
}

func copyChunk(ctx context.Context, destination io.Writer, path string, buffer []byte) (int64, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer file.Close()
	hash := sha256.New()
	writer := io.MultiWriter(destination, hash)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, "", err
		}
		n, readErr := file.Read(buffer)
		if n > 0 {
			written, writeErr := writer.Write(buffer[:n])
			total += int64(written)
			if writeErr != nil {
				return total, "", writeErr
			}
			if written != n {
				return total, "", io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return total, "", readErr
		}
	}
	return total, hex.EncodeToString(hash.Sum(nil)), nil
}
