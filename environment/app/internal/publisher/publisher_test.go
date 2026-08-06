package publisher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishValidChunks(t *testing.T) {
	directory := t.TempDir()
	chunks := [][]byte{[]byte("first\n"), nil, []byte("third payload\n")}
	manifest := writeManifest(t, directory, chunks)
	destination := filepath.Join(directory, "archive", "artifact.bin")
	result, err := New().Publish(context.Background(), manifest, destination)
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	expected := append(append(append([]byte(nil), chunks[0]...), chunks[1]...), chunks[2]...)
	observed, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(observed) != string(expected) || result.Size != int64(len(expected)) {
		t.Fatalf("published bytes = %q, result = %+v", observed, result)
	}
	digest := sha256.Sum256(expected)
	if result.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("digest = %s", result.SHA256)
	}
}

func TestManifestRejectsTraversalAndUnknownFields(t *testing.T) {
	for name, raw := range map[string]string{
		"traversal": `{"version":1,"artifact_size":0,"artifact_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","chunks":[{"path":"../outside","size":0,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}]}`,
		"unknown":   `{"version":1,"artifact_size":0,"artifact_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","chunks":[],"surprise":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := LoadManifest(path); err == nil {
				t.Fatal("LoadManifest() unexpectedly succeeded")
			}
		})
	}
}

func writeManifest(t *testing.T, directory string, chunks [][]byte) string {
	t.Helper()
	manifest := Manifest{Version: 1}
	artifactHash := sha256.New()
	for index, data := range chunks {
		name := filepath.Join("chunks", string(rune('a'+index))+".bin")
		absolute := filepath.Join(directory, name)
		if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(absolute, data, 0o600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		manifest.Chunks = append(manifest.Chunks, Chunk{Path: name, Size: int64(len(data)), SHA256: hex.EncodeToString(digest[:])})
		manifest.ArtifactSize += int64(len(data))
		artifactHash.Write(data)
	}
	manifest.ArtifactSHA256 = hex.EncodeToString(artifactHash.Sum(nil))
	path := filepath.Join(directory, "manifest.json")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(file).Encode(manifest); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
