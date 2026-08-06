package publisher

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Chunk struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Version        int     `json:"version"`
	ArtifactSize   int64   `json:"artifact_size"`
	ArtifactSHA256 string  `json:"artifact_sha256"`
	Chunks         []Chunk `json:"chunks"`
}

func LoadManifest(path string) (Manifest, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, "", fmt.Errorf("read manifest: %w", err)
	}
	if len(raw) > 8<<20 {
		return Manifest{}, "", errors.New("manifest exceeds 8 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, "", fmt.Errorf("decode manifest: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Manifest{}, "", errors.New("manifest has multiple JSON values")
		}
		return Manifest{}, "", fmt.Errorf("decode manifest trailing data: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, "", err
	}
	directory, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return Manifest{}, "", fmt.Errorf("resolve manifest directory: %w", err)
	}
	return manifest, directory, nil
}

func (m Manifest) Validate() error {
	if m.Version != 1 {
		return fmt.Errorf("manifest version must be 1, got %d", m.Version)
	}
	if len(m.Chunks) == 0 || len(m.Chunks) > 4096 {
		return errors.New("manifest must contain between 1 and 4096 chunks")
	}
	if m.ArtifactSize < 0 {
		return errors.New("artifact_size cannot be negative")
	}
	if err := validateDigest(m.ArtifactSHA256); err != nil {
		return fmt.Errorf("artifact_sha256: %w", err)
	}
	var total int64
	seen := make(map[string]struct{}, len(m.Chunks))
	for index, chunk := range m.Chunks {
		if chunk.Path == "" {
			return fmt.Errorf("chunk %d path is empty", index)
		}
		if filepath.IsAbs(chunk.Path) {
			return fmt.Errorf("chunk %d path must be relative", index)
		}
		clean := filepath.Clean(chunk.Path)
		if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return fmt.Errorf("chunk %d path escapes manifest directory", index)
		}
		if clean != chunk.Path {
			return fmt.Errorf("chunk %d path is not canonical", index)
		}
		if _, ok := seen[clean]; ok {
			return fmt.Errorf("chunk %d repeats path %q", index, clean)
		}
		seen[clean] = struct{}{}
		if chunk.Size < 0 {
			return fmt.Errorf("chunk %d size is negative", index)
		}
		if err := validateDigest(chunk.SHA256); err != nil {
			return fmt.Errorf("chunk %d sha256: %w", index, err)
		}
		if total > int64(^uint64(0)>>1)-chunk.Size {
			return errors.New("chunk size total overflows int64")
		}
		total += chunk.Size
	}
	if total != m.ArtifactSize {
		return fmt.Errorf("chunk sizes total %d differs from artifact_size %d", total, m.ArtifactSize)
	}
	return nil
}

func validateDigest(encoded string) error {
	if len(encoded) != 64 {
		return errors.New("digest must contain 64 lowercase hexadecimal characters")
	}
	if encoded != strings.ToLower(encoded) {
		return errors.New("digest must be lowercase")
	}
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != 32 {
		return errors.New("digest is not valid SHA-256")
	}
	return nil
}
