package fixture

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"example.com/durable-relay/internal/publisher"
)

type Mode string

const (
	ModeValid       Mode = "valid"
	ModeMissingLate Mode = "missing-late"
	ModeCorruptLate Mode = "corrupt-late"
)

type Options struct {
	Root      string
	Mode      Mode
	Chunks    int
	ChunkSize int
	Seed      string
}

type Summary struct {
	Root           string `json:"root"`
	Manifest       string `json:"manifest"`
	Mode           Mode   `json:"mode"`
	Chunks         int    `json:"chunks"`
	ChunkSize      int    `json:"chunk_size"`
	ArtifactSize   int64  `json:"artifact_size"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	MissingPath    string `json:"missing_path,omitempty"`
	CorruptPath    string `json:"corrupt_path,omitempty"`
}

func Generate(options Options) (Summary, error) {
	if options.Root == "" {
		return Summary{}, errors.New("fixture root is required")
	}
	if options.Chunks < 1 || options.Chunks > 4096 {
		return Summary{}, errors.New("chunks must be between 1 and 4096")
	}
	if options.ChunkSize < 0 || options.ChunkSize > 32<<20 {
		return Summary{}, errors.New("chunk-size must be between 0 and 33554432")
	}
	switch options.Mode {
	case ModeValid, ModeMissingLate, ModeCorruptLate:
	default:
		return Summary{}, fmt.Errorf("unknown fixture mode %q", options.Mode)
	}
	absolute, err := filepath.Abs(options.Root)
	if err != nil {
		return Summary{}, err
	}
	if entries, err := os.ReadDir(absolute); err == nil && len(entries) != 0 {
		return Summary{}, fmt.Errorf("fixture root %s is not empty", absolute)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Summary{}, err
	}
	chunksDir := filepath.Join(absolute, "chunks")
	if err := os.MkdirAll(chunksDir, 0o750); err != nil {
		return Summary{}, err
	}

	manifest := publisher.Manifest{Version: 1}
	artifactHash := sha256.New()
	var artifactSize int64
	var missingPath, corruptPath string
	for index := 0; index < options.Chunks; index++ {
		data := deterministicBytes(options.Seed, index, options.ChunkSize)
		digest := sha256.Sum256(data)
		relative := filepath.Join("chunks", fmt.Sprintf("chunk-%04d.bin", index))
		absoluteChunk := filepath.Join(absolute, relative)
		manifest.Chunks = append(manifest.Chunks, publisher.Chunk{
			Path:   relative,
			Size:   int64(len(data)),
			SHA256: hex.EncodeToString(digest[:]),
		})
		artifactHash.Write(data)
		artifactSize += int64(len(data))
		last := index == options.Chunks-1
		if options.Mode == ModeMissingLate && last {
			missingPath = absoluteChunk
			continue
		}
		toWrite := data
		if options.Mode == ModeCorruptLate && last {
			toWrite = append([]byte(nil), data...)
			if len(toWrite) == 0 {
				toWrite = []byte{0xff}
			} else {
				toWrite[len(toWrite)/2] ^= 0x80
			}
			corruptPath = absoluteChunk
		}
		if err := os.WriteFile(absoluteChunk, toWrite, 0o640); err != nil {
			return Summary{}, err
		}
	}
	manifest.ArtifactSize = artifactSize
	manifest.ArtifactSHA256 = hex.EncodeToString(artifactHash.Sum(nil))
	manifestPath := filepath.Join(absolute, "manifest.json")
	file, err := os.OpenFile(manifestPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return Summary{}, err
	}
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(manifest); err != nil {
		file.Close()
		return Summary{}, err
	}
	if err := file.Close(); err != nil {
		return Summary{}, err
	}
	return Summary{
		Root:           absolute,
		Manifest:       manifestPath,
		Mode:           options.Mode,
		Chunks:         options.Chunks,
		ChunkSize:      options.ChunkSize,
		ArtifactSize:   artifactSize,
		ArtifactSHA256: manifest.ArtifactSHA256,
		MissingPath:    missingPath,
		CorruptPath:    corruptPath,
	}, nil
}

func deterministicBytes(seed string, chunkIndex, size int) []byte {
	result := make([]byte, size)
	var counter uint64
	position := 0
	for position < len(result) {
		hash := sha256.New()
		hash.Write([]byte(seed))
		var encoded [16]byte
		binary.LittleEndian.PutUint64(encoded[0:8], uint64(chunkIndex))
		binary.LittleEndian.PutUint64(encoded[8:16], counter)
		hash.Write(encoded[:])
		block := hash.Sum(nil)
		position += copy(result[position:], block)
		counter++
	}
	return result
}
