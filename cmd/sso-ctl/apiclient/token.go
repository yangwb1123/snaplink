package apiclient

// T-8a mint/claims/revoke round trip, T-8d unregistered-scope probe, T-9
// credential-less introspection probe. The claims matrix lives in
// claims.go; the shared redaction helpers in sweep.go. All
// credential-bearing probes go through apiclient (probeClient) with
// body credentials, targeted at the advertised endpoints only.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// runT8a executes the T-8a group: mint, claims matrix, revoke, post-revoke
// introspection. A skipped group (no advertised token_endpoint) prints no
// stdout line and forces `check INCOMPLETE`.
func (ck *checker) runT8a() (ok, skipped bool) {
	if ck.doc == nil || ck.doc.TokenEndpoint == "" {
		fmt.Fprintln(os.Stderr, "check: T-8a skipped: advertised token_endpoint absent")
		return false, true
	}
	failed := false
	token, diags := ck.mint()
	for _, d := range diags {
		fmt.Fprintln(os.Stderr, d)
		failed = true
	}
	if token == "" {
		fmt.Fprintln(os.Stdout, "mint: FAIL")
		return false, false
	}
	for _, d := range ck.loadJWKS() {
		fmt.Fprintln(os.Stderr, d)
		failed = true
	}
	for _, d := range ck.verifyClaims() {
		fmt.Fprintln(os.Stderr, d)
		failed = true
	}
	for _, d := range ck.revoke(token) {
		fmt.Fprintln(os.Stderr, d)
		failed = true
	}
	if failed {
		fmt.Fprintln(os.Stdout, "mint: FAIL")
		return false, false
	}
	fmt.Fprintln(os.Stdout, "mint: OK")
	return true, false
}

// mint performs the client-credentials mint against the advertised
// token_endpoint and decodes the JWT header/payload. The minted token is
// returned for the revoke leg; it is never echoed in any diagnostic. The
// advertised URL is preflighted first (row-2 rule): a malformed value must
// fail without any request and without the HTTP layer echoing it raw.
func (ck *checker) mint() (string, []string) {
	if err := validateAdvertisedURL(ck.doc.TokenEndpoint); err != nil {
		return "", []string{fmt.Sprintf("mint: token_endpoint %s: %s; row failed", redactURL(ck.doc.TokenEndpoint), err.Error())}
	}
	body := map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     ck.clientID,
		"client_secret": ck.clientSecret,
	}
	if ck.scope != "" {
		body["scope"] = ck.scope
	}
	if len(ck.resources) > 0 {
		body["resource"] = ck.resources
	}
	client := probeClient(ck.doc.TokenEndpoint)
	resp, err := client.Post("", body)
	if err != nil {
		return "", []string{"mint: " + redactURL(err.Error())}
	}
	raw, rerr := ReadBody(resp)
	if rerr != nil {
		return "", []string{"mint: " + rerr.Error()}
	}
	if resp.StatusCode != http.StatusOK {
		// Body echo only for non-2xx (sanitized, truncated): a 200-without-
		// access_token body would contain the real token, so that branch
		// never echoes the body.
		return "", []string{fmt.Sprintf("mint: status %d%s", resp.StatusCode, bodyEcho(raw))}
	}
	var out struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", []string{"mint: decode response: " + err.Error()}
	}
	if out.AccessToken == "" {
		return "", []string{"mint: response has no access_token"}
	}
	if out.RefreshToken != "" {
		return "", []string{"mint: unexpected refresh_token in cc response"}
	}
	header, payload, err := decodeJWT(out.AccessToken)
	if err != nil {
		return "", []string{"mint: decode access token: " + err.Error()}
	}
	ck.header, ck.payload = header, payload
	return out.AccessToken, nil
}

// revoke runs the revoke + post-revoke introspection legs of T-8a against
// the advertised revocation/introspection endpoints. Both advertised URLs
// are preflighted (row-2 rule) so a malformed value never reaches the HTTP
// layer, whose url.Error would echo it raw.
func (ck *checker) revoke(token string) []string {
	if ck.doc.RevocationEndpoint == "" {
		// Unreachable against a snaplink server (revocation_endpoint is
		// unconditional in buildBaseMetadata); fail rather than probe an
		// unadvertised canonical path.
		return []string{"revoke: advertised revocation_endpoint absent"}
	}
	if err := validateAdvertisedURL(ck.doc.RevocationEndpoint); err != nil {
		return []string{"revoke: revocation_endpoint " + redactURL(ck.doc.RevocationEndpoint) + ": " + err.Error() + "; row failed"}
	}
	client := probeClient(ck.doc.RevocationEndpoint)
	resp, err := client.Post("", map[string]any{
		"token": token, "client_id": ck.clientID, "client_secret": ck.clientSecret,
	})
	if err != nil {
		return []string{"revoke: " + redactURL(err.Error())}
	}
	if _, rerr := ReadBody(resp); rerr != nil {
		return []string{"revoke: " + rerr.Error()}
	}
	if resp.StatusCode != http.StatusOK {
		return []string{fmt.Sprintf("revoke: status %d, expected 200", resp.StatusCode)}
	}
	return ck.postRevokeIntrospect(token)
}

// postRevokeIntrospect runs the T-8a post-revoke introspection leg: the
// revoked token must introspect to active:false. Extracted from revoke to
// hold the function within the 50-line budget.
func (ck *checker) postRevokeIntrospect(token string) []string {
	if ck.doc.IntrospectionEndpoint == "" {
		return []string{"revoke: advertised introspection_endpoint absent"}
	}
	if err := validateAdvertisedURL(ck.doc.IntrospectionEndpoint); err != nil {
		return []string{"revoke: introspection_endpoint " + redactURL(ck.doc.IntrospectionEndpoint) + ": " + err.Error() + "; row failed"}
	}
	iresp, err := probeClient(ck.doc.IntrospectionEndpoint).Post("", map[string]any{
		"token": token, "client_id": ck.clientID, "client_secret": ck.clientSecret,
	})
	if err != nil {
		return []string{"revoke: " + redactURL(err.Error())}
	}
	raw, rerr := ReadBody(iresp)
	if rerr != nil {
		return []string{"revoke: " + rerr.Error()}
	}
	if iresp.StatusCode != http.StatusOK {
		return []string{fmt.Sprintf("revoke: post-revoke introspect: status %d, expected 200", iresp.StatusCode)}
	}
	var out struct {
		Active any `json:"active"`
	}
	_ = json.Unmarshal(raw, &out)
	if active, ok := out.Active.(bool); !ok || active {
		return []string{fmt.Sprintf("revoke: token still active after revoke (active=%v)", out.Active)}
	}
	return nil
}

// runT8d executes the T-8d unregistered-scope probe: POST the randomized
// probe scope to the advertised token_endpoint and require a byte-identical
// 400 {"error":"invalid_scope"}. A 200 means enforcement is absent — the
// probe scope was granted.
func (ck *checker) runT8d(probeScope string) (ok, skipped bool) {
	if ck.doc == nil || ck.doc.TokenEndpoint == "" {
		fmt.Fprintln(os.Stderr, "check: T-8d skipped: advertised token_endpoint absent")
		return false, true
	}
	fail := func(diag string) bool {
		fmt.Fprintln(os.Stderr, diag)
		fmt.Fprintln(os.Stdout, "invalid_scope: FAIL")
		return false
	}
	if err := validateAdvertisedURL(ck.doc.TokenEndpoint); err != nil {
		return fail(fmt.Sprintf("invalid_scope probe: token_endpoint %s: %s; row failed", redactURL(ck.doc.TokenEndpoint), err.Error())), false
	}
	client := probeClient(ck.doc.TokenEndpoint)
	resp, err := client.Post("", map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     ck.clientID,
		"client_secret": ck.clientSecret,
		"scope":         probeScope,
	})
	if err != nil {
		return fail("invalid_scope probe: " + redactURL(err.Error())), false
	}
	raw, rerr := ReadBody(resp)
	if rerr != nil {
		return fail("invalid_scope probe: " + rerr.Error()), false
	}
	const wantBody = `{"error":"invalid_scope"}` + "\n"
	if resp.StatusCode == http.StatusOK {
		// 200 = enforcement absent (empty allowlist AND unwired registry).
		// Body-less by design: the body is a real token for the probe scope.
		return fail("invalid_scope not enforced: probe scope was granted — the client's AllowedScopes is empty or no global scope registry is wired"), false
	}
	if resp.StatusCode != http.StatusBadRequest {
		return fail(fmt.Sprintf("invalid_scope probe: status %d body %s; expected 400", resp.StatusCode, string(sanitizeBody(raw)))), false
	}
	var out struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(raw, &out)
	if out.Error != "" && out.Error != "invalid_scope" {
		return fail(fmt.Sprintf("invalid_scope probe: error code %q, expected \"invalid_scope\"", out.Error)), false
	}
	if string(raw) != wantBody {
		return fail(fmt.Sprintf("invalid_scope probe: status 400 body %s; expected %q", string(sanitizeBody(raw)), wantBody)), false
	}
	fmt.Fprintln(os.Stdout, "invalid_scope: OK")
	return true, false
}

// runT9 executes the T-9 credential-less introspection probe against the
// advertised introspection_endpoint (it doubles as the T-2 matrix row for
// that field and is issued exactly once per run). The bare client is
// structurally bearer-less: apiclient.New's SSO_ADMIN_TOKEN fallback cannot
// apply, and URL userinfo is rejected below.
func (ck *checker) runT9() (ok, skipped bool) {
	if ck.doc == nil || ck.doc.IntrospectionEndpoint == "" {
		fmt.Fprintln(os.Stderr, "check: T-9 skipped: introspection_endpoint not advertised")
		return false, true
	}
	fail := func(diag string) bool {
		fmt.Fprintln(os.Stderr, diag)
		fmt.Fprintln(os.Stdout, "introspect: FAIL")
		return false
	}
	target := ck.doc.IntrospectionEndpoint
	if err := validateAdvertisedURL(target); err != nil {
		return fail(fmt.Sprintf("endpoint introspection_endpoint %s: %s; row failed", redactURL(target), err.Error())), false
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: RejectRedirect}
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(`{"token":"sweep-probe-dummy"}`))
	if err != nil {
		return fail("introspect probe: " + err.Error()), false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fail("introspect probe: " + redactURL(err.Error())), false
	}
	raw, rerr := ReadBody(resp)
	if rerr != nil {
		return fail("introspect probe: " + rerr.Error()), false
	}
	const wantBody = `{"error":"invalid_client"}` + "\n"
	if resp.StatusCode != http.StatusUnauthorized || string(raw) != wantBody {
		return fail(fmt.Sprintf("introspect probe: status %d body %s; expected 401 %s", resp.StatusCode, string(sanitizeBody(raw)), strings.TrimSuffix(wantBody, "\n"))), false
	}
	fmt.Fprintln(os.Stdout, "introspect: OK")
	return true, false
}
