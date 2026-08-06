package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"example.com/durable-relay/internal/ledger"
	"example.com/durable-relay/internal/snapshot"
	"example.com/durable-relay/internal/wal"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "relayinspect: %v\n", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("usage: relayinspect <wal|snapshot|receipts|artifact> [flags]")
	}
	switch arguments[0] {
	case "wal":
		return inspectWAL(arguments[1:])
	case "snapshot":
		return inspectSnapshot(arguments[1:])
	case "receipts":
		return inspectReceipts(arguments[1:])
	case "artifact":
		return inspectArtifact(arguments[1:])
	default:
		return fmt.Errorf("unknown inspector %q", arguments[0])
	}
}

func inspectWAL(arguments []string) error {
	set := flag.NewFlagSet("wal", flag.ContinueOnError)
	path := set.String("path", "", "WAL path")
	if err := set.Parse(arguments); err != nil {
		return err
	}
	if *path == "" || set.NArg() != 0 {
		return errors.New("wal requires exactly -path")
	}
	result, err := wal.ScanStrict(*path)
	if err != nil {
		return err
	}
	result.Events = nil
	return printJSON(result)
}

func inspectSnapshot(arguments []string) error {
	set := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	path := set.String("path", "", "snapshot path")
	if err := set.Parse(arguments); err != nil {
		return err
	}
	if *path == "" || set.NArg() != 0 {
		return errors.New("snapshot requires exactly -path")
	}
	value, exists, err := snapshot.New(*path).Load()
	if err != nil {
		return err
	}
	return printJSON(map[string]any{
		"exists":        exists,
		"version":       value.Version,
		"last_sequence": value.LastSequence,
		"jobs":          len(value.Jobs),
		"created_at":    value.CreatedAt,
	})
}

func inspectReceipts(arguments []string) error {
	set := flag.NewFlagSet("receipts", flag.ContinueOnError)
	path := set.String("path", "", "receipt ledger path")
	requestID := set.String("request", "", "optional request id filter")
	countOnly := set.Bool("count-only", false, "print only the matching count")
	if err := set.Parse(arguments); err != nil {
		return err
	}
	if *path == "" || set.NArg() != 0 {
		return errors.New("receipts requires exactly -path")
	}
	receipts, err := ledger.Scan(*path)
	if err != nil {
		return err
	}
	filtered := receipts[:0]
	for _, receipt := range receipts {
		if *requestID == "" || receipt.RequestID == *requestID {
			filtered = append(filtered, receipt)
		}
	}
	if *countOnly {
		fmt.Println(len(filtered))
		return nil
	}
	return printJSON(map[string]any{"count": len(filtered), "receipts": filtered})
}

func inspectArtifact(arguments []string) error {
	set := flag.NewFlagSet("artifact", flag.ContinueOnError)
	path := set.String("path", "", "artifact path")
	expectedSHA := set.String("sha256", "", "optional expected SHA-256")
	expectedSize := set.Int64("size", -1, "optional expected size")
	if err := set.Parse(arguments); err != nil {
		return err
	}
	if *path == "" || set.NArg() != 0 {
		return errors.New("artifact requires exactly -path")
	}
	file, err := os.Open(*path)
	if err != nil {
		return err
	}
	hash := sha256.New()
	size, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	if *expectedSize >= 0 && size != *expectedSize {
		return fmt.Errorf("artifact size %d, expected %d", size, *expectedSize)
	}
	if *expectedSHA != "" && digest != *expectedSHA {
		return fmt.Errorf("artifact sha256 %s, expected %s", digest, *expectedSHA)
	}
	return printJSON(map[string]any{"path": *path, "size": size, "sha256": digest})
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
