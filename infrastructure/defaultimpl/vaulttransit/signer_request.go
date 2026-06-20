package vaulttransit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// vaultError is the relevant slice of a Vault error response body
// ({"errors":["..."]}). Vault's own error strings are operational (policy
// denied, key not found) and carry no secret, so surfacing the FIRST one aids
// diagnosis — but we never echo the request body or the token.
type vaultError struct {
	Errors []string `json:"errors"`
}

// doRequest performs one bounded Vault round-trip, setting the per-request
// X-Vault-Token (from TokenSource) and optional X-Vault-Namespace, and reads +
// closes the body. A non-2xx status maps to a fail-closed error carrying the
// status and Vault's own error message(s) — but NEVER the token (it is only
// ever a request header, never read back or logged). reqBody nil sends no body.
func (s *Signer) doRequest(ctx context.Context, method, path string, reqBody []byte) ([]byte, error) {
	// Per-request token: the operator owns lifecycle/renewal. Called every
	// request so a renewing source (AppRole, k8s auth, agent sink) is honored.
	token, err := s.cfg.TokenSource(ctx)
	if err != nil {
		// Do not wrap-print the token-source internals beyond its own error;
		// the error must not carry the token itself (it does not — TokenSource
		// returns (token, err) separately, and we discard token on err).
		return nil, fmt.Errorf("vaulttransit: obtain Vault token: %w", err)
	}
	if token == "" {
		return nil, errors.New("vaulttransit: TokenSource returned an empty token")
	}

	var bodyReader io.Reader
	if reqBody != nil {
		bodyReader = bytes.NewReader(reqBody)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, s.baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("vaulttransit: build request: %w", err)
	}
	httpReq.Header.Set("X-Vault-Token", token)
	if s.cfg.Namespace != "" {
		httpReq.Header.Set("X-Vault-Namespace", s.cfg.Namespace)
	}
	if reqBody != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	resp, err := s.client.Do(httpReq)
	if err != nil {
		// Transport error (DNS, TLS verify failure, connection refused,
		// deadline). The url.Error here wraps the request URL, NOT the headers,
		// so the token is not exposed.
		return nil, fmt.Errorf("vaulttransit: %s %s: %w", method, vaultTransitOpName(path), err)
	}
	defer func() { _ = resp.Body.Close() }()
	// Bound the body read so a misbehaving/hostile endpoint can't stream
	// unbounded data into the signing goroutine. Transit replies are small
	// (a public-key PEM or a base64 signature); 1 MiB is generous headroom.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("vaulttransit: read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Fail closed. Surface Vault's own error message(s) (operational, not
		// secret) but NEVER the token or the request body.
		msg := vaultErrorMessage(body)
		if msg != "" {
			return nil, fmt.Errorf("vaulttransit: %s %s: status %d: %s", method, vaultTransitOpName(path), resp.StatusCode, msg)
		}
		return nil, fmt.Errorf("vaulttransit: %s %s: status %d", method, vaultTransitOpName(path), resp.StatusCode)
	}
	return body, nil
}

// vaultErrorMessage extracts the first error string from a Vault error body, or
// "" if the body is not the expected shape. Used only for diagnostics.
func vaultErrorMessage(body []byte) string {
	var ve vaultError
	if err := json.Unmarshal(body, &ve); err != nil {
		return ""
	}
	if len(ve.Errors) == 0 {
		return ""
	}
	return ve.Errors[0]
}

// vaultTransitOpName reduces a request path to a coarse operation name
// ("sign"/"read-key"/"transit") for error messages, so the key NAME (the last
// path segment) is not echoed into logs/errors. The key name is not secret, but
// keeping it out of errors avoids leaking which key a failing replica targets.
func vaultTransitOpName(path string) string {
	switch {
	case strings.Contains(path, "/sign/"):
		return "transit sign"
	case strings.Contains(path, "/keys/"):
		return "transit read-key"
	default:
		return "transit"
	}
}
