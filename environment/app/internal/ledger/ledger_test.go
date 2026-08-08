package ledger

import (
	"path/filepath"
	"testing"
	"time"

	"example.com/durable-relay/internal/model"
)

func TestAppendAndScanReceipts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	ledger, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 3; index++ {
		receipt := model.Receipt{
			Version:        1,
			JobID:          "job-" + string(rune('a'+index)),
			RequestID:      "request-" + string(rune('a'+index)),
			Destination:    "archive.bin",
			ArtifactSize:   int64(index),
			ArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			CompletedAt:    time.Now().UTC(),
		}
		if err := ledger.Append(receipt); err != nil {
			t.Fatal(err)
		}
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	receipts, err := Scan(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 3 || receipts[2].ArtifactSize != 2 {
		t.Fatalf("unexpected receipts: %+v", receipts)
	}
}
