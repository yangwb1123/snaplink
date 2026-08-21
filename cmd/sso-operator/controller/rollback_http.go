package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type rollbackRequestBody struct {
	Reason            string `json:"reason"`
	ExpectedVersionID string `json:"expected_version_id"`
}

func postConfigRollback(ctx context.Context, hc *http.Client, baseURL, token, expectedID, reason string) (*configApplyResponse, int, error) {
	payload, err := json.Marshal(rollbackRequestBody{Reason: reason, ExpectedVersionID: expectedID})
	if err != nil {
		return nil, 0, fmt.Errorf("encode rollback request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+rollbackPath+"?"+approveQuery, bytes.NewReader(payload))
	if err != nil {
		return nil, 0, fmt.Errorf("build rollback request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request %s: %w", rollbackPath, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read rollback response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("%s returned %d: %s", rollbackPath, resp.StatusCode, describeAPIError(body))
	}
	var parsed configApplyResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("decode rollback response: %w", err)
	}
	return &parsed, resp.StatusCode, nil
}
