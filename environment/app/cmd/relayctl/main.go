package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"example.com/durable-relay/internal/client"
	"example.com/durable-relay/internal/model"
)

type globalOptions struct {
	address string
	timeout time.Duration
	pretty  bool
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "relayctl: %v\n", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	global := flag.NewFlagSet("relayctl", flag.ContinueOnError)
	address := global.String("addr", "http://127.0.0.1:8787", "relayqd origin")
	timeout := global.Duration("timeout", 30*time.Second, "request or operation timeout")
	pretty := global.Bool("pretty", false, "indent JSON output")
	global.SetOutput(os.Stderr)
	if err := global.Parse(arguments); err != nil {
		return err
	}
	remaining := global.Args()
	if len(remaining) == 0 {
		return usageError()
	}
	api, err := client.New(*address, *timeout)
	if err != nil {
		return err
	}
	options := globalOptions{address: *address, timeout: *timeout, pretty: *pretty}
	command, commandArguments := remaining[0], remaining[1:]
	switch command {
	case "submit":
		return submit(api, options, commandArguments)
	case "get":
		return get(api, options, commandArguments)
	case "list":
		return list(api, options, commandArguments)
	case "wait":
		return wait(api, options, commandArguments)
	case "health":
		return health(api, options, commandArguments)
	case "stats":
		return stats(api, options, commandArguments)
	case "reload":
		return reload(api, options, commandArguments)
	case "compact":
		return compact(api, options, commandArguments)
	case "flood":
		return flood(api, options, commandArguments)
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func usageError() error {
	return errors.New("usage: relayctl [global flags] <submit|get|list|wait|health|stats|reload|compact|flood> [flags]")
}

func submit(api *client.Client, options globalOptions, arguments []string) error {
	set := flag.NewFlagSet("submit", flag.ContinueOnError)
	requestID := set.String("request", "", "idempotency request identifier")
	manifest := set.String("manifest", "", "manifest path visible to relayqd")
	destination := set.String("destination", "", "final artifact path")
	attempts := set.Int("max-attempts", 0, "per-job attempt override")
	if err := set.Parse(arguments); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return fmt.Errorf("submit: unexpected arguments: %v", set.Args())
	}
	ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
	defer cancel()
	result, err := api.Submit(ctx, model.JobSpec{
		RequestID:   *requestID,
		Manifest:    *manifest,
		Destination: *destination,
		MaxAttempts: *attempts,
	})
	if err != nil {
		return err
	}
	return printJSON(result, options.pretty)
}

func get(api *client.Client, options globalOptions, arguments []string) error {
	set := flag.NewFlagSet("get", flag.ContinueOnError)
	id := set.String("id", "", "job identifier")
	if err := set.Parse(arguments); err != nil {
		return err
	}
	if *id == "" || set.NArg() != 0 {
		return errors.New("get requires exactly -id")
	}
	ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
	defer cancel()
	job, err := api.Get(ctx, *id)
	if err != nil {
		return err
	}
	return printJSON(job, options.pretty)
}

func list(api *client.Client, options globalOptions, arguments []string) error {
	set := flag.NewFlagSet("list", flag.ContinueOnError)
	requestID := set.String("request", "", "idempotency request identifier")
	if err := set.Parse(arguments); err != nil {
		return err
	}
	if *requestID == "" || set.NArg() != 0 {
		return errors.New("list requires exactly -request")
	}
	ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
	defer cancel()
	jobs, err := api.List(ctx, *requestID)
	if err != nil {
		return err
	}
	return printJSON(model.JobList{Jobs: jobs}, options.pretty)
}

func wait(api *client.Client, options globalOptions, arguments []string) error {
	set := flag.NewFlagSet("wait", flag.ContinueOnError)
	id := set.String("id", "", "job identifier")
	requestID := set.String("request", "", "request identifier; must map to one job")
	interval := set.Duration("poll", 20*time.Millisecond, "poll interval")
	if err := set.Parse(arguments); err != nil {
		return err
	}
	if (*id == "") == (*requestID == "") || set.NArg() != 0 {
		return errors.New("wait requires exactly one of -id or -request")
	}
	ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
	defer cancel()
	for {
		var job model.Job
		if *id != "" {
			observed, err := api.Get(ctx, *id)
			if err != nil {
				return err
			}
			job = observed
		} else {
			jobs, err := api.List(ctx, *requestID)
			if err != nil {
				return err
			}
			if len(jobs) == 0 {
				if err := pause(ctx, *interval); err != nil {
					return err
				}
				continue
			}
			if len(jobs) != 1 {
				return fmt.Errorf("request %q maps to %d jobs", *requestID, len(jobs))
			}
			job = jobs[0]
		}
		if job.Terminal() {
			if err := printJSON(job, options.pretty); err != nil {
				return err
			}
			if job.Status != model.StatusSucceeded {
				return fmt.Errorf("job %s finished with status %s: %s", job.ID, job.Status, job.LastError)
			}
			return nil
		}
		if err := pause(ctx, *interval); err != nil {
			return err
		}
	}
}

func health(api *client.Client, options globalOptions, arguments []string) error {
	if len(arguments) != 0 {
		return errors.New("health takes no arguments")
	}
	ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
	defer cancel()
	value, err := api.Health(ctx)
	if err != nil {
		return err
	}
	return printJSON(value, options.pretty)
}

func stats(api *client.Client, options globalOptions, arguments []string) error {
	if len(arguments) != 0 {
		return errors.New("stats takes no arguments")
	}
	ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
	defer cancel()
	value, err := api.Stats(ctx)
	if err != nil {
		return err
	}
	return printJSON(value, options.pretty)
}

func reload(api *client.Client, options globalOptions, arguments []string) error {
	if len(arguments) != 0 {
		return errors.New("reload takes no arguments")
	}
	ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
	defer cancel()
	value, err := api.Reload(ctx)
	if err != nil {
		return err
	}
	return printJSON(value, options.pretty)
}

func compact(api *client.Client, options globalOptions, arguments []string) error {
	if len(arguments) != 0 {
		return errors.New("compact takes no arguments")
	}
	ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
	defer cancel()
	if err := api.Compact(ctx); err != nil {
		return err
	}
	return printJSON(map[string]bool{"compacted": true}, options.pretty)
}

type floodSummary struct {
	Requested int      `json:"requested"`
	Accepted  int64    `json:"accepted"`
	Failed    int64    `json:"failed"`
	JobIDs    []string `json:"job_ids"`
}

func flood(api *client.Client, options globalOptions, arguments []string) error {
	set := flag.NewFlagSet("flood", flag.ContinueOnError)
	manifest := set.String("manifest", "", "manifest path")
	destinationDir := set.String("destination-dir", "", "directory for unique output paths")
	prefix := set.String("prefix", "load", "request id prefix")
	count := set.Int("count", 200, "number of jobs")
	parallel := set.Int("parallel", 32, "concurrent submitters")
	if err := set.Parse(arguments); err != nil {
		return err
	}
	if *manifest == "" || *destinationDir == "" || *count < 1 || *parallel < 1 || set.NArg() != 0 {
		return errors.New("flood requires -manifest, -destination-dir, and positive count/parallel")
	}
	if *parallel > *count {
		*parallel = *count
	}
	ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
	defer cancel()
	indices := make(chan int)
	ids := make(chan string, *count)
	var accepted atomic.Int64
	var failed atomic.Int64
	var group sync.WaitGroup
	for worker := 0; worker < *parallel; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range indices {
				result, err := api.Submit(ctx, model.JobSpec{
					RequestID:   fmt.Sprintf("%s-%06d", *prefix, index),
					Manifest:    *manifest,
					Destination: filepath.Join(*destinationDir, fmt.Sprintf("artifact-%06d.bin", index)),
				})
				if err != nil {
					failed.Add(1)
					continue
				}
				accepted.Add(1)
				ids <- result.Job.ID
			}
		}()
	}
	go func() {
		defer close(indices)
		for index := 0; index < *count; index++ {
			select {
			case <-ctx.Done():
				return
			case indices <- index:
			}
		}
	}()
	group.Wait()
	close(ids)
	jobIDs := make([]string, 0, accepted.Load())
	for id := range ids {
		jobIDs = append(jobIDs, id)
	}
	summary := floodSummary{Requested: *count, Accepted: accepted.Load(), Failed: failed.Load(), JobIDs: jobIDs}
	if err := printJSON(summary, options.pretty); err != nil {
		return err
	}
	if failed.Load() != 0 {
		return fmt.Errorf("%d submissions failed", failed.Load())
	}
	return nil
}

func pause(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func printJSON(value any, pretty bool) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if pretty {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(value)
}
