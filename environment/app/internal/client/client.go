package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"example.com/durable-relay/internal/config"
	"example.com/durable-relay/internal/engine"
	"example.com/durable-relay/internal/model"
)

type Client struct {
	baseURL string
	http    *http.Client
}

type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("relay API status %d %s: %s", e.Status, e.Code, e.Message)
}

func New(address string, timeout time.Duration) (*Client, error) {
	parsed, err := url.Parse(address)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "http" || parsed.Host == "" || parsed.Path != "" {
		return nil, errors.New("address must be an http://host:port origin without a path")
	}
	return &Client{
		baseURL: strings.TrimSuffix(address, "/"),
		http:    &http.Client{Timeout: timeout},
	}, nil
}

func (c *Client) Submit(ctx context.Context, spec model.JobSpec) (model.SubmitResult, error) {
	var result model.SubmitResult
	err := c.jsonRequest(ctx, http.MethodPost, "/v1/jobs", spec, &result)
	return result, err
}

func (c *Client) Get(ctx context.Context, id string) (model.Job, error) {
	var job model.Job
	err := c.jsonRequest(ctx, http.MethodGet, "/v1/jobs/"+url.PathEscape(id), nil, &job)
	return job, err
}

func (c *Client) List(ctx context.Context, requestID string) ([]model.Job, error) {
	var list model.JobList
	path := "/v1/jobs?request_id=" + url.QueryEscape(requestID)
	err := c.jsonRequest(ctx, http.MethodGet, path, nil, &list)
	return list.Jobs, err
}

func (c *Client) Health(ctx context.Context) (engine.Health, error) {
	var health engine.Health
	err := c.jsonRequest(ctx, http.MethodGet, "/v1/health", nil, &health)
	return health, err
}

func (c *Client) Stats(ctx context.Context) (engine.Stats, error) {
	var stats engine.Stats
	err := c.jsonRequest(ctx, http.MethodGet, "/v1/stats", nil, &stats)
	return stats, err
}

func (c *Client) Reload(ctx context.Context) (config.Snapshot, error) {
	var snapshot config.Snapshot
	err := c.jsonRequest(ctx, http.MethodPost, "/v1/admin/reload", emptyBody{}, &snapshot)
	return snapshot, err
}

func (c *Client) Compact(ctx context.Context) error {
	var response map[string]any
	return c.jsonRequest(ctx, http.MethodPost, "/v1/admin/compact", emptyBody{}, &response)
}

type emptyBody struct{}

func (c *Client) jsonRequest(ctx context.Context, method, path string, requestValue, responseValue any) error {
	var body io.Reader
	if requestValue != nil {
		if _, ok := requestValue.(emptyBody); !ok {
			raw, err := json.Marshal(requestValue)
			if err != nil {
				return err
			}
			body = bytes.NewReader(raw)
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 16<<20))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var envelope struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return &APIError{Status: response.StatusCode, Code: "invalid_error", Message: string(raw)}
		}
		return &APIError{Status: response.StatusCode, Code: envelope.Error.Code, Message: envelope.Error.Message}
	}
	if responseValue == nil {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(responseValue); err != nil {
		return fmt.Errorf("decode API response: %w", err)
	}
	return nil
}
