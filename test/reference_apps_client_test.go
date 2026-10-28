package ssotest

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
)

type refAppResponse struct {
	status int
	body   map[string]any
	header http.Header
	raw    []byte
}

type refAppGrant struct {
	binding                               refAppClient
	code, verifier, nonce, state, session string
}

type refAppTokens struct {
	binding                      refAppClient
	access, refresh, id, session string
}

func refAppRandom(t *testing.T) string {
	t.Helper()
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatal("generate authorization transaction")
	}
	return base64.RawURLEncoding.EncodeToString(value[:])
}

func refAppRead(t *testing.T, response *http.Response, err error) refAppResponse {
	t.Helper()
	if err != nil {
		t.Fatal("reference HTTP request failed")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal("read reference HTTP response")
	}
	out := refAppResponse{status: response.StatusCode, header: response.Header, raw: raw, body: map[string]any{}}
	if len(bytes.TrimSpace(raw)) != 0 && json.Unmarshal(raw, &out.body) != nil {
		t.Fatal("reference response is not a JSON object")
	}
	return out
}

func refAppNoStore(t *testing.T, response refAppResponse) {
	t.Helper()
	if response.header.Get("Cache-Control") != "no-store" || response.header.Get("Pragma") != "no-cache" {
		t.Fatalf("status=%d response is cacheable", response.status)
	}
}

func refAppWant(t *testing.T, response refAppResponse, status int, errorCode string) {
	t.Helper()
	if response.status != status || (errorCode != "" && response.body["error"] != errorCode) {
		t.Fatalf("status/error=%d/%v, want %d/%s", response.status, response.body["error"], status, errorCode)
	}
}

func (h *referenceApps) postJSON(t *testing.T, browser, path string, body map[string]any, bearer string) refAppResponse {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal("encode reference request")
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, h.base+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal("create reference request")
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := h.browsers[browser].Do(req)
	out := refAppRead(t, response, err)
	refAppNoStore(t, out)
	return out
}

func (h *referenceApps) postForm(t *testing.T, path string, client refAppClient, form url.Values) refAppResponse {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, h.base+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal("create reference form request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ID, client.Secret)
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	out := refAppRead(t, response, err)
	refAppNoStore(t, out)
	return out
}

func (h *referenceApps) begin(t *testing.T, binding refAppClient, resume bool, scopes []string) refAppGrant {
	t.Helper()
	grant := refAppGrant{binding: binding, verifier: refAppRandom(t), nonce: refAppRandom(t), state: refAppRandom(t)}
	challenge := sha256.Sum256([]byte(grant.verifier))
	body := map[string]any{"client_id": binding.ID, "redirect_uri": binding.Redirect, "response_type": "code", "scope": scopes,
		"resource": []string{binding.Audience}, "state": grant.state, "nonce": grant.nonce,
		"code_challenge": base64.RawURLEncoding.EncodeToString(challenge[:]), "code_challenge_method": "S256"}
	if resume {
		body["resume_session"] = true
	} else {
		body["provider"], body["credential"] = "password", map[string]string{"username": "user-" + binding.Tenant, "password": refAppPassword}
	}
	result := h.postJSON(t, binding.Tenant, core.PathLogin, body, "")
	refAppWant(t, result, http.StatusOK, "")
	grant.code, _ = result.body["code"].(string)
	grant.session, _ = result.body["session_id"].(string)
	if grant.code == "" || grant.session == "" || result.body["state"] != grant.state || result.body["iss"] != h.base {
		t.Fatal("code response lost transaction/session/issuer binding")
	}
	return grant
}

func (g refAppGrant) form() url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "code": {g.code}, "redirect_uri": {g.binding.Redirect}, "code_verifier": {g.verifier}}
}

func (h *referenceApps) exchange(t *testing.T, grant refAppGrant) refAppTokens {
	t.Helper()
	result := h.postForm(t, core.PathToken, grant.binding, grant.form())
	refAppWant(t, result, http.StatusOK, "")
	tokens := refAppTokens{binding: grant.binding, session: grant.session}
	tokens.access, _ = result.body[core.KeyAccessToken].(string)
	tokens.refresh, _ = result.body[core.KeyRefreshToken].(string)
	tokens.id, _ = result.body[core.KeyIDToken].(string)
	if tokens.access == "" || tokens.refresh == "" || tokens.id == "" {
		t.Fatal("OIDC code response omitted credentials")
	}
	h.verifyID(t, tokens, grant.nonce)
	return tokens
}

func (h *referenceApps) verifyID(t *testing.T, tokens refAppTokens, nonce string) map[string]any {
	t.Helper()
	parts := strings.Split(tokens.id, ".")
	if len(parts) != 3 {
		t.Fatal("ID token is not compact JWS")
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	var selection struct{ Kid, Alg, Typ string }
	if err != nil || json.Unmarshal(header, &selection) != nil || selection.Alg != "EdDSA" || selection.Typ != "JWT" {
		t.Fatal("unexpected ID token header")
	}
	key, err := h.cache.GetJWK(t.Context(), selection.Kid)
	if err != nil {
		t.Fatal("fetch ID-token verification key")
	}
	payload, err := security.VerifyCompactJWS(tokens.id, []core.JWK{key}, map[string]struct{}{"EdDSA": {}})
	if err != nil {
		t.Fatal("ID token signature did not verify")
	}
	claims := map[string]any{}
	if json.Unmarshal(payload, &claims) != nil {
		t.Fatal("invalid signed ID-token claims")
	}
	hash := sha512.Sum512([]byte(tokens.access))
	if claims["iss"] != h.base || claims["aud"] != tokens.binding.ID || claims["nonce"] != nonce || claims["sid"] != tokens.session ||
		claims["sub"] != "user-"+tokens.binding.Tenant || claims["at_hash"] != base64.RawURLEncoding.EncodeToString(hash[:len(hash)/2]) {
		t.Fatal("ID token lost issuer/audience/subject/nonce/session/access binding")
	}
	expires, _ := claims["exp"].(float64)
	if expires <= float64(time.Now().Unix()) {
		t.Fatal("ID token already expired")
	}
	return claims
}

func (h *referenceApps) api(t *testing.T, app, mode, tenantID, bearer string) refAppResponse {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.apis[app].URL+"/"+mode+"/"+tenantID, nil)
	if err != nil {
		t.Fatal("create resource request")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	out := refAppRead(t, response, err)
	refAppNoStore(t, out)
	return out
}

func (h *referenceApps) accessClaims(t *testing.T, tokens refAppTokens) *rs.Claims {
	t.Helper()
	claims, err := rs.ValidateToken(t.Context(), tokens.access, rs.Config{Issuer: h.base, ExpectedAud: tokens.binding.Audience, AllowedAlgs: []string{"EdDSA"}, JWKSCache: h.cache})
	if err != nil {
		t.Fatal("access token validation failed")
	}
	return claims
}
