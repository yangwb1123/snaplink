package ssotest

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	echoadapter "github.com/yangwb1123/snaplink/interfaces/adapters/echo"
	ginadapter "github.com/yangwb1123/snaplink/interfaces/adapters/gin"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/test/testkit"
)

// routerBackends is the matrix dimension: every supported Router backend must
// pass the same protocol scenarios and unmatched-response normalization.
// Public constructors only, default wiring — the production embedding shape.
var routerBackends = []struct {
	name string
	new  func() sso.Router
}{
	{"std", func() sso.Router { return sso.NewStdRouter() }},
	{"gin", func() sso.Router { return ginadapter.NewGinRouter() }},
	{"echo", func() sso.Router { return echoadapter.NewEchoRouter() }},
}

// matrixProbePath tripwires the WithRouter pass-through: if testkit drops
// it, the probe 404s and every scenario fails.
const matrixProbePath = "/__matrix_probe"

// matrixResponse is the observable response surface the matrix compares.
type matrixResponse struct {
	status  int
	body    []byte
	headers http.Header
}

// newMatrixHarness builds a testkit harness on the supplied router.
func newMatrixHarness(t *testing.T, rt sso.Router) *testkit.Harness {
	t.Helper()
	rt.GET(matrixProbePath, func(ctx sso.HandlerContext) {
		ctx.JSON(http.StatusOK, map[string]string{"probe": "ok"})
	})
	h := testkit.NewServer(testkit.WithRouter(rt))
	t.Cleanup(h.Close)
	return h
}

// wireRequest sends one wire request; errors are returned for worker use.
func wireRequest(h *testkit.Harness, method, path, contentType, body, dpop string) (matrixResponse, error) {
	req, err := http.NewRequest(method, h.URL+path, strings.NewReader(body))
	if err != nil {
		return matrixResponse{}, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if dpop != "" {
		req.Header.Set("DPoP", dpop)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return matrixResponse{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return matrixResponse{}, err
	}
	return matrixResponse{status: resp.StatusCode, body: raw, headers: resp.Header.Clone()}, nil
}

func matrixReq(t *testing.T, h *testkit.Harness, method, path, contentType, body, dpop string) matrixResponse {
	t.Helper()
	resp, err := wireRequest(h, method, path, contentType, body, dpop)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

// matrixJSON sends a JSON request (nil body => none) and decodes it.
func matrixJSON(t *testing.T, h *testkit.Harness, method, path string, body map[string]any, dpop string) (matrixResponse, map[string]any) {
	t.Helper()
	var raw, ct string
	if body != nil {
		b, _ := json.Marshal(body)
		raw, ct = string(b), "application/json"
	}
	resp := matrixReq(t, h, method, path, ct, raw, dpop)
	out := map[string]any{}
	_ = json.Unmarshal(resp.body, &out)
	return resp, out
}

// matrixForm posts an x-www-form-urlencoded body and decodes it.
func matrixForm(t *testing.T, h *testkit.Harness, path string, form url.Values, dpop string) (matrixResponse, map[string]any) {
	t.Helper()
	resp := matrixReq(t, h, http.MethodPost, path, "application/x-www-form-urlencoded", form.Encode(), dpop)
	out := map[string]any{}
	_ = json.Unmarshal(resp.body, &out)
	return resp, out
}

// matrixRecorder runs the request through the full handler at recorder level
// (no Date, HEAD bodies preserved) for exact unmatched-surface comparison.
func matrixRecorder(t *testing.T, h *testkit.Harness, method, path string) matrixResponse {
	t.Helper()
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return matrixResponse{status: rec.Code, body: rec.Body.Bytes(), headers: rec.Header().Clone()}
}

// httpNotFoundReference is the runtime-derived unmatched-surface baseline.
func httpNotFoundReference(t *testing.T, method, path string) matrixResponse {
	t.Helper()
	rec := httptest.NewRecorder()
	http.NotFound(rec, httptest.NewRequest(method, path, nil))
	return matrixResponse{status: rec.Code, body: rec.Body.Bytes(), headers: rec.Header().Clone()}
}

// assertNoStore pins the credential-endpoint cache contract (AGENTS.md §3).
func assertNoStore(t *testing.T, resp matrixResponse) {
	t.Helper()
	if got := resp.headers.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := resp.headers.Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache", got)
	}
}

// pkceS256 is the RFC 7636 S256 transformation.
func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// matrixLoginBody is the password login payload for the seeded harness user.
func matrixLoginBody() map[string]any {
	return map[string]any{
		"provider":   "password",
		"client_id":  testkit.DefaultClientID,
		"credential": map[string]string{"username": testkit.DefaultUsername, "password": testkit.DefaultPassword},
	}
}

// authCodeForm is the authorization_code exchange form, optionally carrying
// the PKCE verifier.
func authCodeForm(code, verifier string) url.Values {
	f := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {testkit.DefaultClientID},
		"client_secret": {testkit.DefaultClientSecret},
		"redirect_uri":  {testkit.DefaultRedirectURI},
	}
	if verifier != "" {
		f["code_verifier"] = []string{verifier}
	}
	return f
}

// matrixCode obtains an authorization code via a code-flow login.
func matrixCode(t *testing.T, h *testkit.Harness, challenge, dpop string) string {
	t.Helper()
	body := matrixLoginBody()
	body["response_type"] = "code"
	body["redirect_uri"] = testkit.DefaultRedirectURI
	if challenge != "" {
		body["code_challenge"] = challenge
		body["code_challenge_method"] = "S256"
	}
	resp, out := matrixJSON(t, h, http.MethodPost, "/auth/login", body, dpop)
	if resp.status != http.StatusOK {
		t.Fatalf("login = %d %v", resp.status, out)
	}
	code, _ := out["code"].(string)
	if code == "" {
		t.Fatalf("no code: %v", out)
	}
	return code
}

// ---------- scenario 1: authorization code + PKCE full flow ----------

func TestRouterBackendMatrix_AuthorizationCodePKCE(t *testing.T) {
	for _, b := range routerBackends {
		t.Run(b.name, func(t *testing.T) {
			h := newMatrixHarness(t, b.new())

			// Tripwire: the injected router is really serving.
			resp, out := matrixJSON(t, h, http.MethodGet, matrixProbePath, nil, "")
			if resp.status != http.StatusOK || out["probe"] != "ok" {
				t.Fatalf("probe = %d %v — WithRouter pass-through lost", resp.status, out)
			}

			verifier := "matrix-verifier-" + randomHex(32) // RFC 7636: >= 43 chars
			body := matrixLoginBody()
			body["response_type"] = "code"
			body["redirect_uri"] = testkit.DefaultRedirectURI
			body["state"] = "matrix-state"
			body["code_challenge"] = pkceS256(verifier)
			body["code_challenge_method"] = "S256"
			resp, out = matrixJSON(t, h, http.MethodPost, "/auth/login", body, "")
			if resp.status != http.StatusOK {
				t.Fatalf("login = %d %v", resp.status, out)
			}
			code, _ := out["code"].(string)
			if code == "" {
				t.Fatalf("no code: %v", out)
			}
			if out["state"] != "matrix-state" {
				t.Errorf("state not echoed: %v", out["state"])
			}

			resp, out = matrixForm(t, h, "/token", authCodeForm(code, verifier), "")
			if resp.status != http.StatusOK {
				t.Fatalf("exchange = %d %v", resp.status, out)
			}
			access, _ := out["access_token"].(string)
			if access == "" {
				t.Errorf("no access_token: %v", out)
			}
			if out["token_type"] != "Bearer" {
				t.Errorf("token_type = %v, want Bearer", out["token_type"])
			}

			// Userinfo round-trip with the minted token.
			req, _ := http.NewRequest(http.MethodGet, h.URL+"/userinfo", nil)
			req.Header.Set("Authorization", "Bearer "+access)
			infoResp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("userinfo: %v", err)
			}
			defer func() { _ = infoResp.Body.Close() }()
			raw, _ := io.ReadAll(infoResp.Body)
			info := map[string]any{}
			_ = json.Unmarshal(raw, &info)
			if infoResp.StatusCode != http.StatusOK {
				t.Fatalf("userinfo = %d %v", infoResp.StatusCode, info)
			}
			if info["id"] != testkit.DefaultUsername {
				t.Errorf("userinfo id = %v, want %s", info["id"], testkit.DefaultUsername)
			}
		})
	}
}

// ---------- scenario 2: refresh rotation and family kill ----------

func TestRouterBackendMatrix_RefreshRotation(t *testing.T) {
	for _, b := range routerBackends {
		t.Run(b.name, func(t *testing.T) {
			h := newMatrixHarness(t, b.new())

			// Login returns refresh_token in the raw body (LoginResult omits it).
			resp, out := matrixJSON(t, h, http.MethodPost, "/auth/login", matrixLoginBody(), "")
			if resp.status != http.StatusOK {
				t.Fatalf("login = %d %v", resp.status, out)
			}
			first, _ := out["refresh_token"].(string)
			if first == "" {
				t.Fatalf("no refresh_token: %v", out)
			}

			refreshForm := func(token string) url.Values {
				return url.Values{
					"grant_type":    {"refresh_token"},
					"refresh_token": {token},
					"client_id":     {testkit.DefaultClientID},
					"client_secret": {testkit.DefaultClientSecret},
				}
			}

			// First rotation: 200 + a NEW refresh token (absolute outcome).
			resp, out = matrixForm(t, h, "/token", refreshForm(first), "")
			if resp.status != http.StatusOK {
				t.Fatalf("rotate = %d %v", resp.status, out)
			}
			rotated, _ := out["refresh_token"].(string)
			if rotated == "" || rotated == first {
				t.Errorf("refresh_token not rotated: %q -> %q", first, rotated)
			}
			if out["access_token"] == "" {
				t.Errorf("no access_token: %v", out)
			}

			// The rotated token still works: 200 + another rotation.
			resp, out = matrixForm(t, h, "/token", refreshForm(rotated), "")
			if resp.status != http.StatusOK {
				t.Errorf("rotated reuse = %d %v", resp.status, out)
			}

			// Old-token reuse kills the whole family: 400 invalid_grant with
			// credential-endpoint cache headers on every backend.
			resp, out = matrixForm(t, h, "/token", refreshForm(first), "")
			if resp.status != http.StatusBadRequest {
				t.Fatalf("old-token reuse = %d %v", resp.status, out)
			}
			if out["error"] != "invalid_grant" {
				t.Errorf("error = %v, want invalid_grant", out["error"])
			}
			assertNoStore(t, resp)

			// The family is fully dead: even the freshly rotated token now
			// fails with the same oracle-safe error.
			resp, out = matrixForm(t, h, "/token", refreshForm(rotated), "")
			if resp.status != http.StatusBadRequest || out["error"] != "invalid_grant" {
				t.Errorf("post-kill rotated reuse = %d %v, want 400 invalid_grant", resp.status, out)
			}
			assertNoStore(t, resp)
		})
	}
}

// ---------- scenario 3: DPoP-bound authorization code ----------

func TestRouterBackendMatrix_DPoPBoundToken(t *testing.T) {
	for _, b := range routerBackends {
		t.Run(b.name, func(t *testing.T) {
			h := newMatrixHarness(t, b.new())
			priv, x := dpopGenKey(t)

			loginProof := signDPoPProof(t, priv, x, http.MethodPost, h.URL+"/auth/login")
			code := matrixCode(t, h, "", loginProof)

			// Same key at exchange (fresh proof): 200.
			exchangeProof := signDPoPProof(t, priv, x, http.MethodPost, h.URL+"/token")
			resp, out := matrixForm(t, h, "/token", authCodeForm(code, ""), exchangeProof)
			if resp.status != http.StatusOK {
				t.Fatalf("exchange = %d %v", resp.status, out)
			}
			if out["access_token"] == "" {
				t.Errorf("no access_token: %v", out)
			}

			// A DIFFERENT key at exchange is rejected even though the proof
			// itself is valid (RFC 9449 §10 binding).
			code2 := matrixCode(t, h, "", loginProof)
			priv2, x2 := dpopGenKey(t)
			wrongProof := signDPoPProof(t, priv2, x2, http.MethodPost, h.URL+"/token")
			resp, out = matrixForm(t, h, "/token", authCodeForm(code2, ""), wrongProof)
			if resp.status != http.StatusBadRequest {
				t.Fatalf("wrong-key exchange = %d %v, want 400", resp.status, out)
			}
			if out["error"] != "invalid_grant" {
				t.Errorf("error = %v, want invalid_grant (oracle-leak collapse)", out["error"])
			}
			assertNoStore(t, resp)
		})
	}
}

// ---------- scenario 4: unmatched-route byte identity ----------

func TestRouterBackendMatrix_UnmatchedRouteByteIdentity(t *testing.T) {
	cases := []struct {
		name, method, path string
	}{
		{"unknown path", http.MethodGet, "/definitely-not-mounted"},
		{"wrong method", http.MethodPost, "/userinfo"},
		{"HEAD on GET-only route", http.MethodHead, "/userinfo"},
		{"trailing slash variant", http.MethodGet, "/userinfo/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ref := httpNotFoundReference(t, tc.method, tc.path)
			got := make([]matrixResponse, len(routerBackends))
			for i, b := range routerBackends {
				h := newMatrixHarness(t, b.new())
				got[i] = matrixRecorder(t, h, tc.method, tc.path)
				// Byte identity vs http.NotFound: status + body + the two
				// contract headers (middleware headers differ by design).
				if got[i].status != ref.status ||
					!bytes.Equal(got[i].body, ref.body) ||
					got[i].headers.Get("Content-Type") != ref.headers.Get("Content-Type") ||
					got[i].headers.Get("X-Content-Type-Options") != ref.headers.Get("X-Content-Type-Options") {
					t.Errorf("%s: not byte-identical to http.NotFound (status=%d body=%q ct=%q)",
						b.name, got[i].status, got[i].body, got[i].headers.Get("Content-Type"))
				}
			}
			// Cross-backend: every backend equals the std backend on the
			// full recorder surface (the middleware chain is identical).
			for i := 1; i < len(got); i++ {
				if got[i].status != got[0].status ||
					!bytes.Equal(got[i].body, got[0].body) ||
					got[i].headers.Get("Content-Type") != got[0].headers.Get("Content-Type") {
					t.Errorf("%s backend differs from std on %s %s", routerBackends[i].name, tc.method, tc.path)
				}
			}
		})
	}
}

// ---------- token error semantics across backends ----------

func TestRouterBackendMatrix_TokenErrorSemantics(t *testing.T) {
	// Wrong PKCE verifier at /token: every backend must return the same
	// status, JSON error value, Content-Type prefix, and no-store headers.
	// JSON bodies compare as values (serializer charset/newline differ by
	// framework — the scoped contract in docs/adapters.md §2).
	bodies := make([]map[string]any, len(routerBackends))
	got := make([]matrixResponse, len(routerBackends))
	for i, b := range routerBackends {
		h := newMatrixHarness(t, b.new())
		code := matrixCode(t, h, pkceS256("matrix-verifier-"+randomHex(32)), "")
		resp, out := matrixForm(t, h, "/token", authCodeForm(code, "definitely-wrong"), "")
		got[i], bodies[i] = resp, out
		if resp.status != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", b.name, resp.status)
		}
		if out["error"] != "invalid_grant" {
			t.Errorf("%s: error = %v, want invalid_grant", b.name, out["error"])
		}
		if ct := resp.headers.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("%s: Content-Type = %q, want application/json prefix", b.name, ct)
		}
		assertNoStore(t, resp)
	}
	// Cross-backend semantic equality vs the std backend.
	stdBody, _ := json.Marshal(bodies[0])
	for i := 1; i < len(routerBackends); i++ {
		if got[i].status != got[0].status {
			t.Errorf("%s: status %d differs from std %d", routerBackends[i].name, got[i].status, got[0].status)
		}
		other, _ := json.Marshal(bodies[i])
		if !bytes.Equal(other, stdBody) {
			t.Errorf("%s: JSON error body %s differs from std %s", routerBackends[i].name, other, stdBody)
		}
		if !strings.HasPrefix(got[i].headers.Get("Content-Type"), "application/json") {
			t.Errorf("%s: Content-Type prefix differs from std", routerBackends[i].name)
		}
	}
}

// ---------- concurrency: Use() + ServeHTTP under -race ----------

func TestRouterBackendMatrix_ConcurrentUse(t *testing.T) {
	for _, b := range routerBackends {
		t.Run(b.name, func(t *testing.T) {
			rt := b.new()
			h := newMatrixHarness(t, rt)
			const workers = 12
			var wg sync.WaitGroup
			errCh := make(chan error, workers*2)
			for i := 0; i < workers; i++ {
				wg.Add(2)
				go func() {
					defer wg.Done()
					resp, err := wireRequest(h, http.MethodPost, "/auth/login", "application/json",
						`{"provider":"password","client_id":"`+testkit.DefaultClientID+
							`","credential":{"username":"`+testkit.DefaultUsername+
							`","password":"`+testkit.DefaultPassword+`"}}`, "")
					if err != nil {
						errCh <- fmt.Errorf("concurrent login: %w", err)
						return
					}
					if resp.status != http.StatusOK {
						errCh <- fmt.Errorf("concurrent login = %d %s", resp.status, resp.body)
						return
					}
					var out map[string]any
					_ = json.Unmarshal(resp.body, &out)
					if out["access_token"] == "" {
						errCh <- fmt.Errorf("concurrent login missing access_token: %s", resp.body)
					}
				}()
				go func() {
					defer wg.Done()
					rt.Use(func(sso.HandlerContext) {}) // concurrent middleware append
				}()
			}
			wg.Wait()
			close(errCh)
			for err := range errCh {
				t.Errorf("%s: %v", b.name, err)
			}

			// Post-loop: a subsequently registered route still works (no
			// concurrent registration — late adds need quiet serving).
			rt.GET("/post-loop", func(ctx sso.HandlerContext) {
				ctx.JSON(http.StatusOK, map[string]string{"post": "loop"})
			})
			resp, out := matrixJSON(t, h, http.MethodGet, "/post-loop", nil, "")
			if resp.status != http.StatusOK || out["post"] != "loop" {
				t.Fatalf("%s: post-loop route = %d %v", b.name, resp.status, out)
			}
		})
	}
}
