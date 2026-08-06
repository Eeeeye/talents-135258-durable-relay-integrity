package fixture

import (
	"os"
	"path/filepath"
	"testing"

	"example.com/durable-relay/internal/publisher"
)

func TestGenerateIsDeterministic(t *testing.T) {
	first, err := Generate(Options{Root: filepath.Join(t.TempDir(), "one"), Mode: ModeValid, Chunks: 3, ChunkSize: 513, Seed: "same"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate(Options{Root: filepath.Join(t.TempDir(), "two"), Mode: ModeValid, Chunks: 3, ChunkSize: 513, Seed: "same"})
	if err != nil {
		t.Fatal(err)
	}
	if first.ArtifactSHA256 != second.ArtifactSHA256 || first.ArtifactSize != second.ArtifactSize {
		t.Fatalf("fixtures differ: %+v %+v", first, second)
	}
}

func TestMissingLateKeepsManifestButOmitsLastChunk(t *testing.T) {
	summary, err := Generate(Options{Root: filepath.Join(t.TempDir(), "fixture"), Mode: ModeMissingLate, Chunks: 2, ChunkSize: 64, Seed: "missing"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(summary.MissingPath); !os.IsNotExist(err) {
		t.Fatalf("missing path stat error = %v", err)
	}
	manifest, _, err := publisher.LoadManifest(summary.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Chunks) != 2 || manifest.ArtifactSize != 128 {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
}
