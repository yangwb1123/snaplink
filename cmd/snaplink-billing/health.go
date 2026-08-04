package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

const (
	pathLivez        = "/livez"
	pathReadyz       = "/readyz"
	pathMetrics      = "/metrics"
	maxJWKSProbeBody = 2 << 20
)

type readyCheck struct {
	name  string
	check func(context.Context) error
}

type healthHandler struct {
	checks  []readyCheck
	timeout time.Duration
}

func registerHealthRoutes(mux *http.ServeMux, health healthHandler) {
	mux.HandleFunc(pathLivez, health.livez)
	mux.HandleFunc(pathReadyz, health.readyz)
}

func (health healthHandler) livez(writer http.ResponseWriter, request *http.Request) {
	if !healthMethod(writer, request) {
		return
	}
	writeHealth(writer, http.StatusOK, map[string]any{"status": "ok"})
}

func (health healthHandler) readyz(writer http.ResponseWriter, request *http.Request) {
	if !healthMethod(writer, request) {
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), health.timeout)
	defer cancel()
	statuses, ready := runReadyChecks(ctx, health.checks)
	status := http.StatusOK
	state := "ok"
	if !ready {
		status = http.StatusServiceUnavailable
		state = "unavailable"
	}
	writeHealth(writer, status, map[string]any{"status": state, "checks": statuses})
}

func healthMethod(writer http.ResponseWriter, request *http.Request) bool {
	if request.Method == http.MethodGet {
		return true
	}
	writer.Header().Set("Allow", http.MethodGet)
	writer.WriteHeader(http.StatusMethodNotAllowed)
	return false
}

type checkResult struct {
	name string
	err  error
}

func runReadyChecks(ctx context.Context, checks []readyCheck) (map[string]string, bool) {
	results := make(chan checkResult, len(checks))
	for _, check := range checks {
		go func(candidate readyCheck) {
			results <- checkResult{name: candidate.name, err: candidate.check(ctx)}
		}(check)
	}
	statuses := make(map[string]string, len(checks))
	ready := true
	for range checks {
		result := <-results
		if result.err != nil {
			statuses[result.name] = "error"
			ready = false
			continue
		}
		statuses[result.name] = "ok"
	}
	return statuses, ready
}

func writeHealth(writer http.ResponseWriter, status int, body any) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(body)
}

func jwksReadyCheck(endpoint string, client *http.Client) func(context.Context) error {
	return func(ctx context.Context) error {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return err
		}
		request.Header.Set("Accept", "application/json")
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		return inspectJWKSResponse(response)
	}
}

func inspectJWKSResponse(response *http.Response) error {
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxJWKSProbeBody))
		return errors.New("JWKS endpoint unavailable")
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("JWKS content type is invalid")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxJWKSProbeBody+1))
	if err != nil || len(body) > maxJWKSProbeBody {
		return errors.New("JWKS response is invalid")
	}
	var document struct {
		Keys []core.JWK `json:"keys"`
	}
	if json.Unmarshal(body, &document) != nil || !hasUsableJWK(document.Keys) {
		return errors.New("JWKS contains no usable signing key")
	}
	return nil
}

func hasUsableJWK(keys []core.JWK) bool {
	for _, key := range keys {
		if key.Kid == "" || key.Use == "enc" {
			continue
		}
		if key.Kty == "OKP" || key.Kty == "EC" || key.Kty == "RSA" {
			return true
		}
	}
	return false
}

func newUpstreamHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
