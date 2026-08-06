package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"example.com/durable-relay/internal/config"
	"example.com/durable-relay/internal/engine"
)

func TestHealthAndProtocolErrorsWithoutNetworkListener(t *testing.T) {
	directory := t.TempDir()
	cfg := config.Default()
	cfg.Listen = "127.0.0.1:9998"
	cfg.StateDir = filepath.Join(directory, "state")
	cfg.WorkerCount = 1
	cfg.SnapshotIntervalMS = 0
	opened, err := engine.Open(config.NewManager(filepath.Join(directory, "config.json"), cfg))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := opened.Engine.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := New(cfg.Listen, opened.Engine, logger)

	tests := []struct {
		name        string
		method      string
		path        string
		body        string
		contentType string
		status      int
		contains    string
	}{
		{name: "health", method: http.MethodGet, path: "/v1/health", status: http.StatusOK, contains: `"ready":true`},
		{name: "unknown", method: http.MethodGet, path: "/v1/absent", status: http.StatusNotFound, contains: `"not_found"`},
		{name: "wrong method", method: http.MethodDelete, path: "/v1/health", status: http.StatusMethodNotAllowed, contains: `"method_not_allowed"`},
		{name: "bad content type", method: http.MethodPost, path: "/v1/jobs", body: `{}`, contentType: "text/plain", status: http.StatusBadRequest, contains: `"invalid_json"`},
		{name: "unknown job field", method: http.MethodPost, path: "/v1/jobs", body: `{"request_id":"r","manifest":"m","destination":"d","other":1}`, contentType: "application/json", status: http.StatusBadRequest, contains: `"invalid_json"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, bytes.NewBufferString(test.body))
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			response := httptest.NewRecorder()
			server.ServeHTTP(response, request)
			if response.Code != test.status || !strings.Contains(response.Body.String(), test.contains) {
				t.Fatalf("response = %d %s", response.Code, response.Body.String())
			}
		})
	}
}
