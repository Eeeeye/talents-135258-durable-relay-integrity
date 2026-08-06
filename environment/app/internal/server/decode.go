package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
)

func decodeJSON(writer http.ResponseWriter, request *http.Request, maximum int64, destination any) error {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("Content-Type must be application/json")
	}
	limited := http.MaxBytesReader(writer, request.Body, maximum)
	defer limited.Close()
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request contains multiple JSON values")
		}
		return fmt.Errorf("decode trailing JSON: %w", err)
	}
	return nil
}

func requireEmptyBody(request *http.Request) error {
	defer request.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(request.Body, 2))
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(raw)) != "" {
		return errors.New("request body must be empty")
	}
	return nil
}
