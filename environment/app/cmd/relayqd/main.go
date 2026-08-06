package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"example.com/durable-relay/internal/config"
	"example.com/durable-relay/internal/engine"
	"example.com/durable-relay/internal/server"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "relayqd: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "configs/dev.json", "path to JSON configuration")
	logLevel := flag.String("log-level", "info", "debug, info, warn, or error")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flag.Args())
	}
	level, err := parseLevel(*logLevel)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		return err
	}
	manager := config.NewManager(*configPath, cfg)
	opened, err := engine.Open(manager)
	if err != nil {
		return fmt.Errorf("open engine: %w", err)
	}
	relay := opened.Engine
	logger.Info("state recovered",
		"jobs", opened.RecoveredJobs,
		"events", opened.RecoveredEvents,
		"warnings", opened.Warnings,
	)

	httpServer := server.New(cfg.Listen, relay, logger)
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- httpServer.ListenAndServe()
	}()

	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)

	for {
		select {
		case err := <-serverErrors:
			if err != nil {
				return shutdown(relay, httpServer, cfg.ShutdownTimeoutMS, err)
			}
			return shutdown(relay, httpServer, cfg.ShutdownTimeoutMS, nil)
		case received := <-signals:
			if received == syscall.SIGHUP {
				snapshot, err := relay.Reload()
				if err != nil {
					logger.Error("configuration reload rejected", "error", err)
				} else {
					logger.Info("configuration reloaded", "generation", snapshot.Generation)
				}
				continue
			}
			logger.Info("shutdown signal received", "signal", received.String())
			return shutdown(relay, httpServer, cfg.ShutdownTimeoutMS, nil)
		}
	}
}

func shutdown(relay *engine.Engine, httpServer *server.Server, timeoutMS int, cause error) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMS)*time.Millisecond)
	defer cancel()
	serverErr := httpServer.Shutdown(ctx)
	engineErr := relay.Close(ctx)
	return errors.Join(cause, serverErr, engineErr)
}

func parseLevel(value string) (slog.Level, error) {
	switch value {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level %q", value)
	}
}
