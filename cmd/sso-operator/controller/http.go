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

// applyPath is appended to cluster B's BaseURL for the declared-baseline
// write. The explicit rollback path lives in rollback.go beside its request
// shape so the apply and rollback contracts cannot silently diverge.
const applyPath = "/api/v1/admin/config/apply"

// approveQuery is the mandatory explicit-approval query string the server
// requires on every apply/rollback write (platform/configaudit.QueryApprove
// == "approve"; a missing/false flag is a hard 400 before any state is
// touched). The operator always sends it — the CR-side approval is the
// one-shot annotation, this is the wire-side confirmation.
const approveQuery = "approve=true"

// applyRequestBody mirrors POST .../config/apply?approve=true's required
// body: the PEER cluster's (already server-redacted) running snapshot, its
// canonical sha256 digest (split-brain guard), and the operator's declared
// reason.
type applyRequestBody struct {
	Snapshot map[string]interface{} `json:"snapshot"`
	Digest   string                 `json:"digest"`
	Reason   string                 `json:"reason"`
}

// configApplyResponse mirrors the apply endpoint's 200 body: the redacted
// applied snapshot, the new version id, its predecessor, and an
// informational redacted patch (the operator only uses Version).
type configApplyResponse struct {
	Applied     map[string]interface{} `json:"applied"`
	Version     string                 `json:"version"`
	PrevVersion string                 `json:"prev_version"`
	Patch       []patchOp              `json:"patch"`
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

// postConfigApply performs the POST against clusterB. On success it returns
// the parsed response with status 200. On failure it returns nil, the HTTP
// status (0 for transport/parse errors), and a token-free error — the
// status lets the caller classify 409 (split-brain conflict) vs 400
// (refused) vs everything else for Status.Apply (see
// docs/design/operator-config-apply.md Decision 3).
func postConfigApply(ctx context.Context, hc *http.Client, baseURL, token, digest, reason string, snapshot map[string]interface{}) (*configApplyResponse, int, error) {
	payload, err := json.Marshal(applyRequestBody{Snapshot: snapshot, Digest: digest, Reason: reason})
	if err != nil {
		return nil, 0, fmt.Errorf("encode apply request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+applyPath+"?"+approveQuery, bytes.NewReader(payload))
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := hc.Do(httpReq)
	if err != nil {
		return nil, 0, fmt.Errorf("request %s: %w", applyPath, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("%s returned %d: %s", applyPath, resp.StatusCode, describeAPIError(body))
	}

	var parsed configApplyResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("decode apply response: %w", err)
	}
	return &parsed, resp.StatusCode, nil
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
