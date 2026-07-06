package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// runningConfigResponse mirrors GET /api/v1/admin/config/running's 200
// body exactly (see AGENTS.md background: {"running": {...}}).
type runningConfigResponse struct {
	Running map[string]interface{} `json:"running"`
}

// clusterDiffRequestBody mirrors POST .../cluster-diff's expected body.
type clusterDiffRequestBody struct {
	Snapshot map[string]interface{} `json:"snapshot"`
}

// patchOp is one RFC 6902 operation as returned by the cluster-diff
// endpoint. Value is left as interface{} — this controller only ever
// counts and reports ops, it never applies them, so it has no need to
// type-assert their shape.
type patchOp struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

// clusterDiffResponse mirrors POST .../cluster-diff's 200 body.
type clusterDiffResponse struct {
	Patch []patchOp `json:"patch"`
}

// apiErrorBody mirrors the {"error": "...", "error_description": "..."}
// shape both endpoints use on non-2xx responses, so a failure message can
// surface the server's own error code instead of just an HTTP status.
type apiErrorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// fetchRunningConfig performs the GET against clusterA and extracts the
// "running" map. Errors NEVER include the bearer token — only the URL,
// status code, and the server's own (token-free) error body.
func fetchRunningConfig(ctx context.Context, hc *http.Client, baseURL, token string) (map[string]interface{}, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+runningConfigPath, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := hc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", runningConfigPath, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %d: %s", runningConfigPath, resp.StatusCode, describeAPIError(body))
	}

	var parsed runningConfigResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode running config response: %w", err)
	}
	if parsed.Running == nil {
		return nil, fmt.Errorf("running config response had no %q field", "running")
	}
	return parsed.Running, nil
}

// postClusterDiff performs the POST against clusterB with snapshot as the
// body and returns the parsed patch array.
func postClusterDiff(ctx context.Context, hc *http.Client, baseURL, token string, snapshot map[string]interface{}) ([]patchOp, error) {
	payload, err := json.Marshal(clusterDiffRequestBody{Snapshot: snapshot})
	if err != nil {
		return nil, fmt.Errorf("encode snapshot: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+clusterDiffPath, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := hc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", clusterDiffPath, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %d: %s", clusterDiffPath, resp.StatusCode, describeAPIError(body))
	}

	var parsed clusterDiffResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode cluster-diff response: %w", err)
	}
	return parsed.Patch, nil
}

// describeAPIError best-effort extracts the {"error", "error_description"}
// shape from a non-2xx body; falls back to a truncated raw body so a
// malformed error response still surfaces something useful in Status
// (never a stack trace, never any request header).
func describeAPIError(body []byte) string {
	var apiErr apiErrorBody
	if err := json.Unmarshal(body, &apiErr); err == nil && apiErr.Error != "" {
		if apiErr.ErrorDescription != "" {
			return fmt.Sprintf("%s: %s", apiErr.Error, apiErr.ErrorDescription)
		}
		return apiErr.Error
	}
	const maxLen = 200
	if len(body) > maxLen {
		return string(body[:maxLen]) + "..."
	}
	return string(body)
}
