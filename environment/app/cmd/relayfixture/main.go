package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"example.com/durable-relay/internal/fixture"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "relayfixture: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	root := flag.String("root", "", "new empty fixture directory")
	mode := flag.String("mode", string(fixture.ModeValid), "valid, missing-late, or corrupt-late")
	chunks := flag.Int("chunks", 3, "number of chunks")
	chunkSize := flag.Int("chunk-size", 262144, "bytes per chunk")
	seed := flag.String("seed", "durable-relay-fixture-v1", "deterministic fixture seed")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flag.Args())
	}
	summary, err := fixture.Generate(fixture.Options{
		Root:      *root,
		Mode:      fixture.Mode(*mode),
		Chunks:    *chunks,
		ChunkSize: *chunkSize,
		Seed:      *seed,
	})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(summary)
}
