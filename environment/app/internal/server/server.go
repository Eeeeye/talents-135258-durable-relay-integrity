package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"example.com/durable-relay/internal/engine"
	"example.com/durable-relay/internal/model"
)

type Server struct {
	engine *engine.Engine
	logger *slog.Logger
	http   *http.Server
}

func New(address string, relay *engine.Engine, logger *slog.Logger) *Server {
	server := &Server{engine: relay, logger: logger}
	server.http = &http.Server{
		Addr:              address,
		Handler:           server,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	return server
}

func (s *Server) ListenAndServe() error {
	listener, err := net.Listen("tcp", s.http.Addr)
	if err != nil {
		return err
	}
	s.logger.Info("HTTP listener ready", "address", listener.Addr().String())
	err = s.http.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	started := time.Now()
	statusWriter := &statusRecorder{ResponseWriter: writer, status: http.StatusOK}
	s.route(statusWriter, request)
	s.logger.Info("HTTP request",
		"method", request.Method,
		"path", request.URL.Path,
		"status", statusWriter.status,
		"duration_ms", time.Since(started).Milliseconds(),
	)
}

func (s *Server) route(writer http.ResponseWriter, request *http.Request) {
	switch {
	case request.URL.Path == "/v1/health":
		if request.Method != http.MethodGet {
			methodNotAllowed(writer, http.MethodGet)
			return
		}
		writeJSON(writer, http.StatusOK, s.engine.Health())
	case request.URL.Path == "/v1/stats":
		if request.Method != http.MethodGet {
			methodNotAllowed(writer, http.MethodGet)
			return
		}
		writeJSON(writer, http.StatusOK, s.engine.Stats())
	case request.URL.Path == "/v1/jobs":
		s.handleJobs(writer, request)
	case strings.HasPrefix(request.URL.Path, "/v1/jobs/"):
		s.handleJob(writer, request)
	case request.URL.Path == "/v1/admin/reload":
		s.handleReload(writer, request)
	case request.URL.Path == "/v1/admin/compact":
		s.handleCompact(writer, request)
	default:
		writeError(writer, http.StatusNotFound, "not_found", "route not found")
	}
}

func (s *Server) handleJobs(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodPost:
		var spec model.JobSpec
		maximum := s.engine.Stats().Config.MaxRequestBytes
		if err := decodeJSON(writer, request, maximum, &spec); err != nil {
			writeError(writer, http.StatusBadRequest, "invalid_json", err.Error())
			return
		}
		result, err := s.engine.Submit(spec)
		if err != nil {
			status := http.StatusBadRequest
			code := "invalid_job"
			if errors.Is(err, engine.ErrQueueFull) {
				status = http.StatusServiceUnavailable
				code = "queue_full"
			}
			writeError(writer, status, code, err.Error())
			return
		}
		status := http.StatusAccepted
		if result.Existing {
			status = http.StatusOK
		}
		writeJSON(writer, status, result)
	case http.MethodGet:
		requestID := request.URL.Query().Get("request_id")
		if requestID == "" || len(request.URL.Query()) != 1 {
			writeError(writer, http.StatusBadRequest, "invalid_query", "exactly one request_id query parameter is required")
			return
		}
		writeJSON(writer, http.StatusOK, model.JobList{Jobs: s.engine.ListByRequest(requestID)})
	default:
		methodNotAllowed(writer, http.MethodGet+", "+http.MethodPost)
	}
}

func (s *Server) handleJob(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	id := strings.TrimPrefix(request.URL.Path, "/v1/jobs/")
	if id == "" || strings.Contains(id, "/") {
		writeError(writer, http.StatusNotFound, "not_found", "job not found")
		return
	}
	job, ok := s.engine.Get(id)
	if !ok {
		writeError(writer, http.StatusNotFound, "not_found", "job not found")
		return
	}
	writeJSON(writer, http.StatusOK, job)
}

func (s *Server) handleReload(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodPost)
		return
	}
	if err := requireEmptyBody(request); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	snapshot, err := s.engine.Reload()
	if err != nil {
		writeError(writer, http.StatusConflict, "reload_rejected", err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, snapshot)
}

func (s *Server) handleCompact(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodPost)
		return
	}
	if err := requireEmptyBody(request); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	if err := s.engine.Compact(); err != nil {
		writeError(writer, http.StatusInternalServerError, "compact_failed", err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"compacted": true, "at": time.Now().UTC()})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecorder) Write(raw []byte) (int, error) {
	return w.ResponseWriter.Write(raw)
}

func AddressURL(address string) string {
	return fmt.Sprintf("http://%s", address)
}
