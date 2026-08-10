package apiclient

// Sweep tests for `sso-ctl check` (T-2/T-8a/T-8d/T-9 probe groups) plus the
// redaction-helper unit tests. Green-path runs use a real in-process
// sso.NewServer (the oidc_discovery_test.go testkit shape, reused by
// pattern); failure rows use a hand-rolled stub with per-path handlers and
// request recording. No external services, no SSO_TEST_* env.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// goldenGreenStdout is the byte-deterministic stdout of a fully green run:
// one constant line per executed probe group, in fixed order, plus the final
// verdict. No URL, status, or count ever reaches stdout.
const goldenGreenStdout = "discovery: OK\nmint: OK\ninvalid_scope: OK\nintrospect: OK\ncheck OK\n"

// cleanSweepEnv force-unsets the sweep env vars so a runner's environment
// can never leak into a test (unless the test sets them itself afterwards).
func cleanSweepEnv(t *testing.T) {
	t.Helper()
	t.Setenv(EnvToken, "")
	t.Setenv(EnvAddr, "")
}

// runCheck executes CheckRun with captured stdout/stderr and returns the
// exit code plus the captured streams.
func runCheck(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	os.Stdout, os.Stderr = wOut, wErr
	code := CheckRun(args)
	os.Stdout, os.Stderr = oldOut, oldErr
	_ = wOut.Close()
	_ = wErr.Close()
	out, _ := io.ReadAll(rOut)
	errB, _ := io.ReadAll(rErr)
	return code, string(out), string(errB)
}

// --- fixture: real in-process server (testkit shape) ---

// newLiveServer builds a real sso.NewServer bound to an httptest listener
// whose URL is the configured issuer, so the advertised endpoints resolve to
// the live server itself. Seeded restricted client demo/s with
// AllowedScopes ["read","write"] doubles as T-8d's precondition. The
// Ed25519 token issuer is configured with the same issuer value
// (cmd/sso-server's WithEd25519Issuer wiring): the sweep asserts
// iss == discovery issuer, and the issuer's default value is a non-URL
// placeholder.
func newLiveServer(t *testing.T) *httptest.Server {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := "http://" + lis.Addr().String()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "demo", Secret: "s", Active: true,
		AllowedScopes: []string{"read", "write"},
	})
	srv := sso.NewServer(
		sso.WithIssuer(addr),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute), defaultimpl.WithEd25519Issuer(addr))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithIDTokenIssuer(defaultimpl.NewEd25519JWTIssuer()),
	)
	httpSrv := &httptest.Server{Listener: lis, Config: &http.Server{Handler: srv.Handler()}}
	httpSrv.Start()
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

// --- fixture: hand-rolled stub ---

// stubCheck is a fake deployment: per-path handlers plus request recording.
// The discovery doc derives from a field map so any endpoint can be
// advertised (or omitted, or pointed at a bad URL).
type stubCheck struct {
	t        *testing.T
	srv      *httptest.Server
	mu       sync.Mutex
	handlers map[string]http.HandlerFunc
	requests []*http.Request

	mintToken  string // when set, /token issues this token for non-probe scopes
	probeResp  func() (int, string)
	t9Resp     func() (int, string)
	postRevoke func() (int, string)
}

func newStubCheck(t *testing.T) *stubCheck {
	s := &stubCheck{
		t: t, handlers: map[string]http.HandlerFunc{},
		probeResp:  func() (int, string) { return http.StatusBadRequest, `{"error":"invalid_scope"}` + "\n" },
		t9Resp:     func() (int, string) { return http.StatusUnauthorized, `{"error":"invalid_client"}` + "\n" },
		postRevoke: func() (int, string) { return http.StatusOK, `{"active":false}` + "\n" },
	}
	s.srv = httptest.NewServer(http.HandlerFunc(s.dispatch))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stubCheck) dispatch(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests = append(s.requests, r.Clone(r.Context()))
	h := s.handlers[r.URL.Path]
	s.mu.Unlock()
	if h == nil {
		http.NotFound(w, r)
		return
	}
	h(w, r)
}

func (s *stubCheck) handle(path string, h http.HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[path] = h
}

func (s *stubCheck) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

func (s *stubCheck) requestsTo(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.requests {
		if r.URL.Path == path {
			n++
		}
	}
	return n
}

func (s *stubCheck) authHeadersTo(path string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, r := range s.requests {
		if r.URL.Path == path {
			out = append(out, r.Header.Get("Authorization"))
		}
	}
	return out
}

// advertiseDoc serves a discovery doc with the given issuer and advertised
// endpoints (field -> URL suffix; empty suffix omits the field).
func (s *stubCheck) advertiseDoc(issuer string, fields map[string]string) {
	doc := map[string]string{"issuer": issuer}
	for field, suffix := range fields {
		if suffix != "" {
			doc[field] = s.srv.URL + suffix
		}
	}
	s.serveDoc(doc)
}

// advertiseDocRaw serves a discovery doc with the given field values
// advertised verbatim — no base-URL prepending. Failure rows use it to
// advertise malformed absolute URLs exactly as written (the prepending
// advertiseDoc would turn "file:///x" into a syntactically different
// value).
func (s *stubCheck) advertiseDocRaw(issuer string, fields map[string]string) {
	doc := map[string]string{"issuer": issuer}
	for field, val := range fields {
		if val != "" {
			doc[field] = val
		}
	}
	s.serveDoc(doc)
}

// serveDoc installs the discovery handler serving the given field map.
func (s *stubCheck) serveDoc(doc map[string]string) {
	body, err := json.Marshal(doc)
	if err != nil {
		s.t.Fatalf("marshal doc: %v", err)
	}
	s.handle(oidcDiscoveryPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
}

// healthy installs a well-behaved deployment mirror on the stub.
func (s *stubCheck) healthy() {
	s.advertiseDoc(s.srv.URL, map[string]string{
		"token_endpoint":         "/token",
		"authorization_endpoint": "/auth/login",
		"jwks_uri":               "/jwks",
		"introspection_endpoint": "/token/introspect",
		"revocation_endpoint":    "/token/revoke",
		"userinfo_endpoint":      "/userinfo",
		"end_session_endpoint":   "/logout",
	})
	s.handle("/token", s.handleToken)
	s.handle("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusFound)
	})
	s.handle("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[{"kty":"OKP","kid":"testkid","crv":"Ed25519","x":"abc"}]}`))
	})
	s.handle("/token/introspect", s.handleIntrospect)
	s.handle("/token/revoke", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}\n"))
	})
	s.handle("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"missing_token"}` + "\n"))
	})
	s.handle("/logout", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusFound)
	})
}

// handleToken mirrors the live /token contract: probe-scope requests get the
// canned invalid_scope response; everything else mints (or serves the
// overridden mint response).
func (s *stubCheck) handleToken(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if bytes.Contains(body, []byte("sweep-probe-")) {
		status, respBody := s.probeResp()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody))
		return
	}
	token := s.mintToken
	if token == "" {
		token = craftJWT(s.t, map[string]any{"alg": "EdDSA", "typ": "at+jwt", "kid": "testkid"},
			map[string]any{"iss": s.srv.URL, "sub": "demo", "client_id": "demo", "jti": "j1", "scope": "read write"})
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(fmt.Sprintf(`{"access_token":%q,"token_type":"Bearer","expires_in":3600,"scope":"read write"}`+"\n", token)))
}

// handleIntrospect mirrors the live contract split: credential-less requests
// (T-9) get 401 invalid_client; authenticated requests (post-revoke) get the
// canned active response.
func (s *stubCheck) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if !bytes.Contains(body, []byte(`"client_id"`)) {
		status, respBody := s.t9Resp()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody))
		return
	}
	status, respBody := s.postRevoke()
	w.WriteHeader(status)
	_, _ = w.Write([]byte(respBody))
}

// craftJWT builds an unsigned-shaped JWT (header.payload.sig). The sweep
// decodes without verifying, so the signature segment is a placeholder.
func craftJWT(t *testing.T, header, payload map[string]any) string {
	t.Helper()
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb) + ".sig"
}

// checkArgs returns the standard credential flags for a stub/live run.
func checkArgs(addr string, extra ...string) []string {
	args := []string{"--addr", addr, "--client-id", "demo", "--client-secret", "s"}
	return append(args, extra...)
}

// --- A1/A8: CLI surface ---

// TestCheck_HelpExitsZero pins the deliberate ErrHelp mapping: with
// ContinueOnError, -h yields flag.ErrHelp; check is the tree's first
// subcommand to map it to exit 0 (usage on stderr, nothing on stdout).
func TestCheck_HelpExitsZero(t *testing.T) {
	cleanSweepEnv(t)
	code, out, errOut := runCheck(t, "-h")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 for -h", code)
	}
	if out != "" {
		t.Errorf("stdout = %q, want empty (help never goes to stdout)", out)
	}
	if !strings.Contains(errOut, "sso-ctl check") || !strings.Contains(errOut, "Usage:") {
		t.Errorf("stderr = %q, want check usage banner", errOut)
	}
}

// TestUsage_RolesContract pins REQ-5: the usage banner documents the
// conditional roles assertion (--expect-roles <set>, absence tolerated), the
// --expect-no-roles cc pin with its rationale, and the server-side emission
// pin held by the infrastructure/defaultimpl issue_payload tests.
func TestUsage_RolesContract(t *testing.T) {
	cleanSweepEnv(t)
	code, _, errOut := runCheck(t, "-h")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 for -h", code)
	}
	for _, want := range []string{
		"--expect-roles",
		"--expect-no-roles",
		"absence is tolerated",
		"infrastructure/defaultimpl",
		"TestTenantRoles_ClaimsPerIssuer",
	} {
		if !strings.Contains(errOut, want) {
			t.Errorf("usage stderr missing %q:\n%s", want, errOut)
		}
	}
}

// TestCheck_NoCredentialsMisuse pins the F-1 exit contract: no credentials
// is missing-required-input misuse (exit 2 + usage), nothing executes.
func TestCheck_NoCredentialsMisuse(t *testing.T) {
	cleanSweepEnv(t)
	stub := newStubCheck(t)
	stub.healthy()
	code, out, errOut := runCheck(t, "--addr", stub.srv.URL)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if out != "" {
		t.Errorf("stdout = %q, want empty (misuse never runs probes)", out)
	}
	if !strings.Contains(errOut, "missing required --client-id and --client-secret") {
		t.Errorf("stderr = %q, want missing-credentials diagnostic", errOut)
	}
	if stub.requestCount() != 0 {
		t.Errorf("stub received %d requests, want 0 (nothing executes on misuse)", stub.requestCount())
	}
}

// TestExitCodes drives the misuse matrix: partial creds, expectation flags
// without creds, bad --addr, unknown flag — all exit 2 with usage on stderr.
func TestExitCodes(t *testing.T) {
	cleanSweepEnv(t)
	stub := newStubCheck(t)
	stub.healthy()
	cases := []struct {
		name string
		args []string
	}{
		{"client-id-only", []string{"--client-id", "demo"}},
		{"client-secret-only", []string{"--client-secret", "s"}},
		{"expect-roles-without-creds", []string{"--expect-roles"}},
		{"expect-roles-no-value", []string{"--client-id", "demo", "--client-secret", "s", "--expect-roles"}},
		{"expect-no-roles-without-creds", []string{"--expect-no-roles"}},
		{"both-roles-flags", []string{"--client-id", "demo", "--client-secret", "s", "--expect-roles", "admin", "--expect-no-roles"}},
		{"scope-without-creds", []string{"--scope", "read"}},
		{"expect-tenant-without-creds", []string{"--expect-tenant-id", "t1"}},
		{"unknown-flag", []string{"--nope"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errOut := runCheck(t, tc.args...)
			if code != 2 {
				t.Fatalf("exit = %d, want 2", code)
			}
			if !strings.Contains(errOut, "Usage:") {
				t.Errorf("stderr missing usage banner: %q", errOut)
			}
		})
	}
}

// TestCheck_AddrValidation drives the M-3 matrix: every invalid --addr shape
// exits 2 before any network activity, and the rejection message never
// echoes the raw value (which may embed credentials).
func TestCheck_AddrValidation(t *testing.T) {
	cleanSweepEnv(t)
	stub := newStubCheck(t)
	stub.healthy()
	cases := []struct {
		name string
		addr string
	}{
		{"no-scheme", "8443"},
		{"empty-host", "http://"},
		{"userinfo", "http://user:pass@host"},
		{"query", "https://host/path?x=1"},
		{"fragment", "https://host/path#f"},
		{"file-scheme", "file:///x"},
		{"bad-port", "https://host:badport"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errOut := runCheck(t, checkArgs(tc.addr)...)
			if code != 2 {
				t.Fatalf("exit = %d, want 2", code)
			}
			// The rejection line must never echo the raw addr (it may embed
			// credentials); the usage banner legitimately documents the
			// DefaultAddr, so the check targets the "invalid base URL:" line.
			for _, line := range strings.Split(errOut, "\n") {
				if !strings.Contains(line, "invalid base URL:") {
					continue
				}
				if strings.Contains(line, tc.addr) {
					t.Errorf("rejection line echoes the raw addr %q: %q", tc.addr, line)
				}
			}
			if stub.requestCount() != 0 {
				t.Errorf("stub received %d requests, want 0 (preflight fails first)", stub.requestCount())
			}
		})
	}
	// A parseable URL passes preflight; the discovery transport error then
	// surfaces as a run failure (exit 1), not misuse (exit 2).
	code, _, errOut := runCheck(t, checkArgs("http://127.0.0.1:1")...)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (preflight passed, discovery failed)", code)
	}
	if !strings.Contains(errOut, "discovery:") {
		t.Errorf("stderr = %q, want discovery failure diagnostic", errOut)
	}
}

// TestCheck_EnvAddrValidation pins the F-3 effective-addr rule: SSO_ADMIN_ADDR
// wins over --addr, a bad env value is exit-2 misuse with zero requests, and
// a valid env value steers the sweep.
func TestCheck_EnvAddrValidation(t *testing.T) {
	cleanSweepEnv(t)
	stub := newStubCheck(t)
	stub.healthy()
	other := newStubCheck(t)
	other.healthy()

	t.Run("bad-env-exits-2", func(t *testing.T) {
		t.Setenv(EnvAddr, "http://user:pass@host")
		code, _, errOut := runCheck(t, checkArgs(stub.srv.URL)...)
		if code != 2 {
			t.Fatalf("exit = %d, want 2", code)
		}
		if strings.Contains(errOut, "user:pass") {
			t.Errorf("stderr echoes the env value: %q", errOut)
		}
		if stub.requestCount() != 0 {
			t.Errorf("stub received %d requests, want 0", stub.requestCount())
		}
	})
	t.Run("bad-env-beats-good-flag", func(t *testing.T) {
		t.Setenv(EnvAddr, "http://")
		code, _, _ := runCheck(t, checkArgs(stub.srv.URL)...)
		if code != 2 {
			t.Fatalf("exit = %d, want 2 (env wins over the flag)", code)
		}
	})
	t.Run("valid-env-steers-sweep", func(t *testing.T) {
		t.Setenv(EnvAddr, stub.srv.URL)
		code, out, _ := runCheck(t, checkArgs(other.srv.URL)...)
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (sweep ran against the env addr)", code)
		}
		if out != goldenGreenStdout {
			t.Errorf("stdout = %q, want %q", out, goldenGreenStdout)
		}
		if other.requestCount() != 0 {
			t.Errorf("flag addr server received %d requests, want 0 (env wins)", other.requestCount())
		}
	})
}

// --- A2/A3/A4: T-2 discovery sweep ---

// TestSweep_GreenPath is the live-server green path: all four groups pass,
// stdout is the golden constant, stderr stays silent.
func TestSweep_GreenPath(t *testing.T) {
	cleanSweepEnv(t)
	srv := newLiveServer(t)
	code, out, errOut := runCheck(t, checkArgs(srv.URL)...)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr:\n%s", code, errOut)
	}
	if out != goldenGreenStdout {
		t.Errorf("stdout = %q, want %q", out, goldenGreenStdout)
	}
	if errOut != "" {
		t.Errorf("stderr = %q, want empty on a green run", errOut)
	}
}

// TestStdoutDeterministic pins byte-determinism: two runs against the same
// server produce byte-identical stdout equal to the checked-in golden.
func TestStdoutDeterministic(t *testing.T) {
	cleanSweepEnv(t)
	srv := newLiveServer(t)
	args := checkArgs(srv.URL)
	code1, out1, _ := runCheck(t, args...)
	code2, out2, _ := runCheck(t, args...)
	if code1 != 0 || code2 != 0 {
		t.Fatalf("exits = %d/%d, want 0/0", code1, code2)
	}
	if out1 != out2 {
		t.Errorf("stdout differs across runs:\n%q\nvs\n%q", out1, out2)
	}
	if out1 != goldenGreenStdout {
		t.Errorf("stdout = %q, want golden %q", out1, goldenGreenStdout)
	}
}

// TestSweep_DiscoveryFetchFail drives row 1: non-200, undecodable JSON,
// empty body, and 302 (content row — never followed) all fail the sweep.
func TestSweep_DiscoveryFetchFail(t *testing.T) {
	cleanSweepEnv(t)
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"status-500", http.StatusInternalServerError, `{"error":"boom"}`, "status 500"},
		{"not-json", http.StatusOK, "not json", "invalid JSON"},
		{"empty-body", http.StatusOK, "", "invalid JSON"},
		{"redirect-302", http.StatusFound, "redirecting", "status 302"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := newStubCheck(t)
			stub.healthy()
			stub.handle(oidcDiscoveryPath, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			code, out, errOut := runCheck(t, checkArgs(stub.srv.URL)...)
			if code != 1 {
				t.Fatalf("exit = %d, want 1", code)
			}
			if !strings.Contains(out, "discovery: FAIL") {
				t.Errorf("stdout = %q, want discovery: FAIL", out)
			}
			if !strings.Contains(errOut, "discovery: GET") || !strings.Contains(errOut, tc.want) {
				t.Errorf("stderr = %q, want discovery diagnostic with %q", errOut, tc.want)
			}
		})
	}
}

// TestSweep_AdvertisedOnly pins advertised-only semantics: a doc without
// userinfo/end_session issues zero probes for them and still passes.
func TestSweep_AdvertisedOnly(t *testing.T) {
	cleanSweepEnv(t)
	stub := newStubCheck(t)
	stub.healthy()
	stub.advertiseDoc(stub.srv.URL, map[string]string{
		"token_endpoint":         "/token",
		"authorization_endpoint": "/auth/login",
		"jwks_uri":               "/jwks",
		"introspection_endpoint": "/token/introspect",
		"revocation_endpoint":    "/token/revoke",
	})
	code, out, errOut := runCheck(t, checkArgs(stub.srv.URL)...)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr:\n%s", code, errOut)
	}
	if out != goldenGreenStdout {
		t.Errorf("stdout = %q, want %q", out, goldenGreenStdout)
	}
	if stub.requestsTo("/userinfo") != 0 || stub.requestsTo("/logout") != 0 {
		t.Error("absent endpoints were probed — advertised-only violated")
	}
}

// TestSweep_404RowFails drives row 3: one unmounted advertised endpoint
// fails its row with the field+method+URL diagnostic.
func TestSweep_404RowFails(t *testing.T) {
	cleanSweepEnv(t)
	stub := newStubCheck(t)
	stub.healthy()
	stub.handle("/token", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	code, out, errOut := runCheck(t, checkArgs(stub.srv.URL)...)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(out, "discovery: FAIL") {
		t.Errorf("stdout = %q, want discovery: FAIL", out)
	}
	if !strings.Contains(errOut, "endpoint token_endpoint POST "+stub.srv.URL+"/token: observed 404, expected non-404") {
		t.Errorf("stderr = %q, want 404 row diagnostic", errOut)
	}
}

// TestSweep_TokenEndpointSuffix drives row 5 (A4): a non-/token-suffixed
// advertised token_endpoint fails with observed vs expected suffix.
func TestSweep_TokenEndpointSuffix(t *testing.T) {
	cleanSweepEnv(t)
	stub := newStubCheck(t)
	stub.healthy()
	stub.advertiseDoc(stub.srv.URL, map[string]string{
		"token_endpoint":         "/oauth2/token",
		"authorization_endpoint": "/auth/login",
		"jwks_uri":               "/jwks",
		"introspection_endpoint": "/token/introspect",
		"revocation_endpoint":    "/token/revoke",
		"userinfo_endpoint":      "/userinfo",
		"end_session_endpoint":   "/logout",
	})
	code, _, errOut := runCheck(t, checkArgs(stub.srv.URL)...)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errOut, `token_endpoint `+stub.srv.URL+`/oauth2/token: path suffix "/oauth2/token" != "/token"`) {
		t.Errorf("stderr = %q, want suffix diagnostic", errOut)
	}
}

// TestSweep_AdvertisedURLRejection drives row 2 + M-5: unparseable,
// non-http(s), relative, empty-host, and userinfo-bearing advertised URLs
// fail the row without any request, and the diagnostic never shows the
// embedded credentials.
func TestSweep_AdvertisedURLRejection(t *testing.T) {
	cleanSweepEnv(t)
	cases := []struct {
		name string
		url  string
		want string
	}{
		{"file-scheme", "file:///x", "scheme must be http or https"},
		{"unparseable", "%zz", "not a valid absolute URL"},
		{"userinfo", "https://u:p@h/token", "must not embed credentials"},
		{"relative", "/token", "scheme must be http or https"},
		{"empty-host", "http:///token", "host is empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := newStubCheck(t)
			stub.healthy()
			// advertiseDocRaw: the malformed token_endpoint must be advertised
			// exactly as written (advertiseDoc would prepend the base URL).
			base := stub.srv.URL
			stub.advertiseDocRaw(stub.srv.URL, map[string]string{
				"token_endpoint":         tc.url,
				"authorization_endpoint": base + "/auth/login",
				"jwks_uri":               base + "/jwks",
				"introspection_endpoint": base + "/token/introspect",
				"revocation_endpoint":    base + "/token/revoke",
				"userinfo_endpoint":      base + "/userinfo",
				"end_session_endpoint":   base + "/logout",
			})
			code, _, errOut := runCheck(t, checkArgs(stub.srv.URL)...)
			if code != 1 {
				t.Fatalf("exit = %d, want 1", code)
			}
			if !strings.Contains(errOut, "endpoint token_endpoint") || !strings.Contains(errOut, tc.want) {
				t.Errorf("stderr = %q, want row-2 diagnostic with %q", errOut, tc.want)
			}
			if strings.Contains(errOut, "u:p") {
				t.Errorf("stderr echoes embedded credentials: %q", errOut)
			}
			if stub.requestsTo("/token") != 0 {
				t.Errorf("/token received %d requests, want 0 (bad URL never probed)", stub.requestsTo("/token"))
			}
		})
	}
}

// TestSweep_TransportErrorRow drives row 4: a closed listener yields
// per-row transport diagnostics, not a crash.
func TestSweep_TransportErrorRow(t *testing.T) {
	cleanSweepEnv(t)
	stub := newStubCheck(t)
	stub.healthy()
	stub.srv.Close()
	code, _, errOut := runCheck(t, checkArgs(stub.srv.URL)...)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errOut, "discovery: GET") {
		t.Errorf("stderr = %q, want discovery transport diagnostic", errOut)
	}
}

// TestSweep_DecoyFieldNotFetched pins the advertised-only coercion guard:
// a decoy registration_endpoint is never fetched, and the issuer value is
// compared, never fetched.
func TestSweep_DecoyFieldNotFetched(t *testing.T) {
	cleanSweepEnv(t)
	stub := newStubCheck(t)
	stub.healthy()
	stub.advertiseDoc(stub.srv.URL, map[string]string{
		"token_endpoint":         "/token",
		"authorization_endpoint": "/auth/login",
		"jwks_uri":               "/jwks",
		"introspection_endpoint": "/token/introspect",
		"revocation_endpoint":    "/token/revoke",
		"userinfo_endpoint":      "/userinfo",
		"end_session_endpoint":   "/logout",
		"registration_endpoint":  "/register",
	})
	code, _, errOut := runCheck(t, checkArgs(stub.srv.URL)...)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr:\n%s", code, errOut)
	}
	if stub.requestsTo("/register") != 0 {
		t.Error("decoy registration_endpoint was fetched")
	}
}

// TestSweep_3xxTruthinessPasses pins M-2: 3xx on the five truthiness rows
// passes ("non-404" without following).
func TestSweep_3xxTruthinessPasses(t *testing.T) {
	cleanSweepEnv(t)
	stub := newStubCheck(t)
	stub.healthy()
	stub.handle("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusFound)
	})
	stub.handle("/token", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) == 0 {
			w.WriteHeader(http.StatusFound) // truthiness row sees 302
			return
		}
		if bytes.Contains(body, []byte("sweep-probe-")) {
			status, respBody := stub.probeResp()
			w.WriteHeader(status)
			_, _ = w.Write([]byte(respBody))
			return
		}
		token := craftJWT(stub.t, map[string]any{"alg": "EdDSA", "typ": "at+jwt", "kid": "testkid"},
			map[string]any{"iss": stub.srv.URL, "sub": "demo", "client_id": "demo", "jti": "j1"})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"access_token":%q}`+"\n", token)))
	})
	stub.handle("/token/revoke", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) == 0 {
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}\n"))
	})
	stub.handle("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusFound)
	})
	stub.handle("/logout", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusFound)
	})
	code, out, errOut := runCheck(t, checkArgs(stub.srv.URL)...)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr:\n%s", code, errOut)
	}
	if out != goldenGreenStdout {
		t.Errorf("stdout = %q, want %q", out, goldenGreenStdout)
	}
}

// TestSweep_3xxContentRowFails pins M-1: content rows (discovery, jwks,
// mint, revoke, introspect-401, invalid_scope-400) fail on any 3xx.
func TestSweep_3xxContentRowFails(t *testing.T) {
	cleanSweepEnv(t)
	cases := []struct {
		name  string
		want  string
		setup func(*stubCheck)
	}{
		{"discovery", "discovery: GET", func(s *stubCheck) {
			s.handle(oidcDiscoveryPath, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusFound)
			})
		}},
		{"jwks", "observed 302, expected 200", func(s *stubCheck) {
			s.handle("/jwks", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusFound)
			})
		}},
		{"mint", "mint: status 302", func(s *stubCheck) {
			s.handle("/token", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusFound)
			})
		}},
		{"revoke", "revoke: status 302, expected 200", func(s *stubCheck) {
			s.handle("/token/revoke", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusFound)
			})
		}},
		{"introspect", "introspect probe: status 302", func(s *stubCheck) {
			s.handle("/token/introspect", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusFound)
			})
		}},
		{"invalid_scope", "invalid_scope probe: status 302", func(s *stubCheck) {
			s.handle("/token", func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if bytes.Contains(body, []byte("sweep-probe-")) {
					w.WriteHeader(http.StatusFound)
					return
				}
				token := craftJWT(s.t, map[string]any{"alg": "EdDSA", "typ": "at+jwt", "kid": "testkid"},
					map[string]any{"iss": s.srv.URL, "sub": "demo", "client_id": "demo", "jti": "j1"})
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(fmt.Sprintf(`{"access_token":%q}`+"\n", token)))
			})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := newStubCheck(t)
			stub.healthy()
			tc.setup(stub)
			code, _, errOut := runCheck(t, checkArgs(stub.srv.URL)...)
			if code != 1 {
				t.Fatalf("exit = %d, want 1", code)
			}
			if !strings.Contains(errOut, tc.want) {
				t.Errorf("stderr = %q, want %q", errOut, tc.want)
			}
		})
	}
}

// TestSweep_RedirectNotFollowed pins the blocking security amendment: a
// 302/307 Location target receives zero requests — the 307 POST body
// (carrying client_secret) is never forwarded.
func TestSweep_RedirectNotFollowed(t *testing.T) {
	cleanSweepEnv(t)
	var mu sync.Mutex
	targetHits := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		targetHits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	t.Run("mint-307-body-not-forwarded", func(t *testing.T) {
		stub := newStubCheck(t)
		stub.healthy()
		stub.handle("/token", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
		})
		code, _, errOut := runCheck(t, checkArgs(stub.srv.URL)...)
		if code != 1 {
			t.Fatalf("exit = %d, want 1", code)
		}
		mu.Lock()
		hits := targetHits
		mu.Unlock()
		if hits != 0 {
			t.Fatalf("307 target received %d requests — mint body would have been forwarded", hits)
		}
		if !strings.Contains(errOut, "mint: status 307") {
			t.Errorf("stderr = %q, want mint 307 diagnostic", errOut)
		}
	})
	t.Run("truthiness-302-not-followed", func(t *testing.T) {
		stub := newStubCheck(t)
		stub.healthy()
		stub.handle("/auth/login", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusFound)
		})
		code, _, errOut := runCheck(t, checkArgs(stub.srv.URL)...)
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (302 on truthiness row passes); stderr:\n%s", code, errOut)
		}
		mu.Lock()
		hits := targetHits
		mu.Unlock()
		if hits != 0 {
			t.Fatalf("302 target received %d requests — Location never fetched", hits)
		}
	})
}

// --- A5: T-8a mint / claims / revoke ---

// TestMint_ClaimsMatrix runs the unconditional claims against the live
// server: kid in JWKS, typ at+jwt, iss == discovery issuer,
// sub/client_id == demo, jti non-empty — all asserted by a green exit.
func TestMint_ClaimsMatrix(t *testing.T) {
	cleanSweepEnv(t)
	srv := newLiveServer(t)
	code, _, errOut := runCheck(t, checkArgs(srv.URL)...)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr:\n%s", code, errOut)
	}
}

// TestMint_ScopeContainsRequested asserts the declared-scope claim path.
func TestMint_ScopeContainsRequested(t *testing.T) {
	cleanSweepEnv(t)
	srv := newLiveServer(t)
	code, _, errOut := runCheck(t, checkArgs(srv.URL, "--scope", "read write")...)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr:\n%s", code, errOut)
	}
}

// TestMint_AudContainsResource asserts both polymorphic aud forms: the live
// server emits an array; a stub-issued string aud is accepted too.
func TestMint_AudContainsResource(t *testing.T) {
	cleanSweepEnv(t)
	t.Run("live-array-form", func(t *testing.T) {
		srv := newLiveServer(t)
		code, _, errOut := runCheck(t, checkArgs(srv.URL, "--resource", "https://api.example")...)
		if code != 0 {
			t.Fatalf("exit = %d, want 0; stderr:\n%s", code, errOut)
		}
	})
	t.Run("stub-string-form", func(t *testing.T) {
		stub := newStubCheck(t)
		stub.healthy()
		stub.mintToken = craftJWT(t, map[string]any{"alg": "EdDSA", "typ": "at+jwt", "kid": "testkid"},
			map[string]any{"iss": stub.srv.URL, "sub": "demo", "client_id": "demo", "jti": "j1", "aud": "https://api.example"})
		code, _, errOut := runCheck(t, checkArgs(stub.srv.URL, "--resource", "https://api.example")...)
		if code != 0 {
			t.Fatalf("exit = %d, want 0; stderr:\n%s", code, errOut)
		}
	})
}

// TestMint_TenantIDExpectation drives row 15: the flag is a declaration —
// a matching tenant_id passes, an absent one fails with "tenant_id absent".
func TestMint_TenantIDExpectation(t *testing.T) {
	cleanSweepEnv(t)
	t.Run("present-matches", func(t *testing.T) {
		stub := newStubCheck(t)
		stub.healthy()
		stub.mintToken = craftJWT(t, map[string]any{"alg": "EdDSA", "typ": "at+jwt", "kid": "testkid"},
			map[string]any{"iss": stub.srv.URL, "sub": "demo", "client_id": "demo", "jti": "j1", "tenant_id": "t1"})
		code, _, errOut := runCheck(t, checkArgs(stub.srv.URL, "--expect-tenant-id", "t1")...)
		if code != 0 {
			t.Fatalf("exit = %d, want 0; stderr:\n%s", code, errOut)
		}
	})
	t.Run("absent-fails", func(t *testing.T) {
		stub := newStubCheck(t)
		stub.healthy()
		code, _, errOut := runCheck(t, checkArgs(stub.srv.URL, "--expect-tenant-id", "t1")...)
		if code != 1 {
			t.Fatalf("exit = %d, want 1", code)
		}
		if !strings.Contains(errOut, "claims: tenant_id absent") {
			t.Errorf("stderr = %q, want tenant_id absent diagnostic", errOut)
		}
	})
}

// stubMintingRoles installs a stub that mints a token carrying the given
// roles value (any JSON shape: []string, string, ...) on the /token path.
func stubMintingRoles(t *testing.T, roles any) *stubCheck {
	t.Helper()
	stub := newStubCheck(t)
	stub.healthy()
	stub.mintToken = craftJWT(t, map[string]any{"alg": "EdDSA", "typ": "at+jwt", "kid": "testkid"},
		map[string]any{"iss": stub.srv.URL, "sub": "demo", "client_id": "demo", "jti": "j1", "roles": roles})
	return stub
}

// TestMint_RolesConditional drives REQ-1: --expect-roles is a conditional
// declared-set assertion. Absence (the live cc mint) is tolerated — the
// landmine inversion: the removed guaranteed-fail test asserted exit 1 for
// exactly this run; a present non-empty roles claim must be set-equal to
// the declared set; a present non-array claim always fails.
func TestMint_RolesConditional(t *testing.T) {
	cleanSweepEnv(t)
	t.Run("live-cc-absence-tolerated", func(t *testing.T) {
		srv := newLiveServer(t)
		code, out, errOut := runCheck(t, checkArgs(srv.URL, "--expect-roles", "admin")...)
		if code != 0 {
			t.Fatalf("exit = %d, want 0; stderr:\n%s", code, errOut)
		}
		if out != goldenGreenStdout {
			t.Errorf("stdout = %q, want %q", out, goldenGreenStdout)
		}
	})
	t.Run("stub-absence-tolerated", func(t *testing.T) {
		// Same semantics without the live-server dependency: a stub token
		// with no roles claim passes --expect-roles (absence is tolerated).
		stub := newStubCheck(t)
		stub.healthy()
		code, out, errOut := runCheck(t, checkArgs(stub.srv.URL, "--expect-roles", "admin")...)
		if code != 0 {
			t.Fatalf("exit = %d, want 0; stderr:\n%s", code, errOut)
		}
		if out != goldenGreenStdout {
			t.Errorf("stdout = %q, want %q", out, goldenGreenStdout)
		}
	})
	t.Run("matching-set-passes", func(t *testing.T) {
		stub := stubMintingRoles(t, []string{"admin"})
		code, _, errOut := runCheck(t, checkArgs(stub.srv.URL, "--expect-roles", "admin")...)
		if code != 0 {
			t.Fatalf("exit = %d, want 0; stderr:\n%s", code, errOut)
		}
	})
	t.Run("declared-missing-fails", func(t *testing.T) {
		stub := stubMintingRoles(t, []string{"admin"})
		code, _, errOut := runCheck(t, checkArgs(stub.srv.URL, "--expect-roles", "ops")...)
		if code != 1 {
			t.Fatalf("exit = %d, want 1", code)
		}
		if !strings.Contains(errOut, "claims: roles [admin] != declared [ops]") {
			t.Errorf("stderr = %q, want observed-vs-declared diagnostic", errOut)
		}
	})
	t.Run("set-equality-order-insensitive", func(t *testing.T) {
		stub := stubMintingRoles(t, []string{"admin", "ops"})
		// Space-separated single argument: stringList splits on Fields.
		code, _, errOut := runCheck(t, checkArgs(stub.srv.URL, "--expect-roles", "ops admin")...)
		if code != 0 {
			t.Fatalf("exit = %d, want 0; stderr:\n%s", code, errOut)
		}
	})
	t.Run("repeatable-flag-equivalent", func(t *testing.T) {
		stub := stubMintingRoles(t, []string{"admin", "ops"})
		code, _, errOut := runCheck(t, checkArgs(stub.srv.URL, "--expect-roles", "ops", "--expect-roles", "admin")...)
		if code != 0 {
			t.Fatalf("exit = %d, want 0; stderr:\n%s", code, errOut)
		}
	})
	t.Run("extra-token-role-fails", func(t *testing.T) {
		stub := stubMintingRoles(t, []string{"admin", "ops"})
		code, _, errOut := runCheck(t, checkArgs(stub.srv.URL, "--expect-roles", "admin")...)
		if code != 1 {
			t.Fatalf("exit = %d, want 1", code)
		}
		if !strings.Contains(errOut, "claims: roles [admin ops] != declared [admin]") {
			t.Errorf("stderr = %q, want extra-token-role diagnostic", errOut)
		}
	})
	t.Run("empty-declared-set-fails-any-claim", func(t *testing.T) {
		stub := stubMintingRoles(t, []string{"admin"})
		code, _, errOut := runCheck(t, checkArgs(stub.srv.URL, "--expect-roles", "")...)
		if code != 1 {
			t.Fatalf("exit = %d, want 1", code)
		}
		if !strings.Contains(errOut, "claims: roles [admin] != declared []") {
			t.Errorf("stderr = %q, want empty-declared diagnostic", errOut)
		}
	})
	t.Run("empty-claim-tolerated", func(t *testing.T) {
		stub := stubMintingRoles(t, []string{})
		code, _, errOut := runCheck(t, checkArgs(stub.srv.URL, "--expect-roles", "admin")...)
		if code != 0 {
			t.Fatalf("exit = %d, want 0; stderr:\n%s", code, errOut)
		}
	})
	t.Run("malformed-string-fails", func(t *testing.T) {
		stub := stubMintingRoles(t, "admin")
		code, _, errOut := runCheck(t, checkArgs(stub.srv.URL, "--expect-roles", "admin")...)
		if code != 1 {
			t.Fatalf("exit = %d, want 1", code)
		}
		if !strings.Contains(errOut, "claims: roles claim is not an array") {
			t.Errorf("stderr = %q, want not-an-array diagnostic", errOut)
		}
	})
}

// TestMint_ExpectNoRoles drives REQ-2: --expect-no-roles is the attainable
// cc-path pin. It always passes on a live server (cc mints never resolve
// Subject.Roles); a non-empty roles claim, or a malformed non-array claim,
// fails; no declaration means no assertion.
func TestMint_ExpectNoRoles(t *testing.T) {
	cleanSweepEnv(t)
	t.Run("live-cc-passes", func(t *testing.T) {
		srv := newLiveServer(t)
		code, out, errOut := runCheck(t, checkArgs(srv.URL, "--expect-no-roles")...)
		if code != 0 {
			t.Fatalf("exit = %d, want 0; stderr:\n%s", code, errOut)
		}
		if out != goldenGreenStdout {
			t.Errorf("stdout = %q, want %q", out, goldenGreenStdout)
		}
	})
	t.Run("roles-present-fails", func(t *testing.T) {
		stub := stubMintingRoles(t, []string{"admin"})
		code, _, errOut := runCheck(t, checkArgs(stub.srv.URL, "--expect-no-roles")...)
		if code != 1 {
			t.Fatalf("exit = %d, want 1", code)
		}
		if !strings.Contains(errOut, "claims: roles present but --expect-no-roles declared") {
			t.Errorf("stderr = %q, want roles-present diagnostic", errOut)
		}
	})
	t.Run("absent-passes", func(t *testing.T) {
		stub := newStubCheck(t)
		stub.healthy()
		code, _, errOut := runCheck(t, checkArgs(stub.srv.URL, "--expect-no-roles")...)
		if code != 0 {
			t.Fatalf("exit = %d, want 0; stderr:\n%s", code, errOut)
		}
	})
	t.Run("malformed-string-fails", func(t *testing.T) {
		stub := stubMintingRoles(t, "admin")
		code, _, errOut := runCheck(t, checkArgs(stub.srv.URL, "--expect-no-roles")...)
		if code != 1 {
			t.Fatalf("exit = %d, want 1", code)
		}
		if !strings.Contains(errOut, "claims: roles claim is not an array") {
			t.Errorf("stderr = %q, want not-an-array diagnostic", errOut)
		}
	})
	t.Run("undeclared-roles-pass", func(t *testing.T) {
		stub := stubMintingRoles(t, []string{"admin"})
		code, _, errOut := runCheck(t, checkArgs(stub.srv.URL)...)
		if code != 0 {
			t.Fatalf("exit = %d, want 0; stderr:\n%s", code, errOut)
		}
	})
}

// TestMint_ResponseFail drives rows 7/8 + the R7 body-echo pin: mint
// failures name the status/decode error; a 200-without-access_token body is
// never echoed (it can contain the token).
func TestMint_ResponseFail(t *testing.T) {
	cleanSweepEnv(t)
	valid := craftJWT(t, map[string]any{"alg": "EdDSA", "typ": "at+jwt", "kid": "testkid"},
		map[string]any{"iss": "https://placeholder", "sub": "demo", "client_id": "demo", "jti": "j1"})
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"status-400", http.StatusBadRequest, `{"error":"invalid_request"}` + "\n", "mint: status 400"},
		{"no-access-token", http.StatusOK, `{"token":"MINTED-BUT-NOT-ACCESS"}` + "\n", "mint: response has no access_token"},
		{"two-part-jwt", http.StatusOK, fmt.Sprintf(`{"access_token":%q}`+"\n", "abc.def"), "mint: decode access token:"},
		{"bad-base64url", http.StatusOK, fmt.Sprintf(`{"access_token":%q}`+"\n", "!!!.!!!.!!!"), "mint: decode access token:"},
		{"refresh-token", http.StatusOK, fmt.Sprintf(`{"access_token":%q,"refresh_token":"rt-1"}`+"\n", valid), "mint: unexpected refresh_token in cc response"},
		{"redirect-302", http.StatusFound, "", "mint: status 302"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := newStubCheck(t)
			stub.healthy()
			body := tc.body
			status := tc.status
			stub.handle("/token", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(body))
			})
			code, _, errOut := runCheck(t, checkArgs(stub.srv.URL)...)
			if code != 1 {
				t.Fatalf("exit = %d, want 1", code)
			}
			if !strings.Contains(errOut, tc.want) {
				t.Errorf("stderr = %q, want %q", errOut, tc.want)
			}
			if strings.Contains(errOut, "MINTED-BUT-NOT-ACCESS") {
				t.Errorf("stderr echoes the 200-without-access_token body: %q", errOut)
			}
		})
	}
}

// TestClaimsMatrix_FailureDiagnostics drives rows 9-14: one data-driven test
// over stub-issued JWTs sharing the matrix verification path.
func TestClaimsMatrix_FailureDiagnostics(t *testing.T) {
	cleanSweepEnv(t)
	baseHeader := map[string]any{"alg": "EdDSA", "typ": "at+jwt", "kid": "testkid"}
	basePayload := map[string]any{"iss": "https://placeholder", "sub": "demo", "client_id": "demo", "jti": "j1", "scope": "read"}
	cases := []struct {
		name   string
		mutate func(h, p map[string]any)
		extra  []string
		want   string
	}{
		{"kid-missing", func(h, p map[string]any) { delete(h, "kid") }, nil, "claims: kid missing"},
		{"kid-not-in-jwks", func(h, p map[string]any) { h["kid"] = "otherkid" }, nil, `claims: kid "otherkid" not in JWKS`},
		{"typ-wrong", func(h, p map[string]any) { h["typ"] = "JWT" }, nil, `claims: typ "JWT" != "at+jwt"`},
		{"iss-wrong", func(h, p map[string]any) { p["iss"] = "https://other.example" }, nil, "claims: iss"},
		{"sub-wrong", func(h, p map[string]any) { p["sub"] = "other" }, nil, `claims: sub "other" != "demo"`},
		{"client-id-wrong", func(h, p map[string]any) { p["client_id"] = "other" }, nil, `claims: client_id "other" != "demo"`},
		{"scope-missing", func(h, p map[string]any) { delete(p, "scope") }, []string{"--scope", "read"}, `claims: scope "" missing "read"`},
		{"aud-missing", func(h, p map[string]any) { delete(p, "aud") }, []string{"--resource", "https://api.example"}, `claims: aud`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := newStubCheck(t)
			stub.healthy()
			h := map[string]any{}
			p := map[string]any{}
			for k, v := range baseHeader {
				h[k] = v
			}
			for k, v := range basePayload {
				p[k] = v
			}
			tc.mutate(h, p)
			stub.mintToken = craftJWT(t, h, p)
			code, _, errOut := runCheck(t, checkArgs(stub.srv.URL, tc.extra...)...)
			if code != 1 {
				t.Fatalf("exit = %d, want 1", code)
			}
			if !strings.Contains(errOut, tc.want) {
				t.Errorf("stderr = %q, want %q", errOut, tc.want)
			}
		})
	}
}

// TestRevoke_RoundTrip is the live-server revoke leg: revoke 200 and
// post-revoke introspect active:false, with a silent stderr.
func TestRevoke_RoundTrip(t *testing.T) {
	cleanSweepEnv(t)
	srv := newLiveServer(t)
	code, _, errOut := runCheck(t, checkArgs(srv.URL)...)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr:\n%s", code, errOut)
	}
}

// TestRevoke_Non200Fails drives row 17.
func TestRevoke_Non200Fails(t *testing.T) {
	cleanSweepEnv(t)
	stub := newStubCheck(t)
	stub.healthy()
	stub.handle("/token/revoke", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}` + "\n"))
	})
	code, _, errOut := runCheck(t, checkArgs(stub.srv.URL)...)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errOut, "revoke: status 500, expected 200") {
		t.Errorf("stderr = %q, want revoke 500 diagnostic", errOut)
	}
}

// TestRevoke_StillActiveFails drives row 18.
func TestRevoke_StillActiveFails(t *testing.T) {
	cleanSweepEnv(t)
	stub := newStubCheck(t)
	stub.healthy()
	stub.postRevoke = func() (int, string) { return http.StatusOK, `{"active":true}` + "\n" }
	code, _, errOut := runCheck(t, checkArgs(stub.srv.URL)...)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errOut, "revoke: token still active after revoke (active=true)") {
		t.Errorf("stderr = %q, want still-active diagnostic", errOut)
	}
}

// --- A6: T-8d invalid_scope probe ---

// TestInvalidScope_ByteExact is the byte-exact green path for T-8d.
func TestInvalidScope_ByteExact(t *testing.T) {
	cleanSweepEnv(t)
	stub := newStubCheck(t)
	stub.healthy()
	code, _, errOut := runCheck(t, checkArgs(stub.srv.URL)...)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr:\n%s", code, errOut)
	}
}

// TestInvalidScope_ExtraFieldFails drives row 19: any extra field breaks the
// byte-identical requirement and the observed body (sanitized) is on stderr.
func TestInvalidScope_ExtraFieldFails(t *testing.T) {
	cleanSweepEnv(t)
	stub := newStubCheck(t)
	stub.healthy()
	stub.probeResp = func() (int, string) { return http.StatusBadRequest, `{"error":"invalid_scope","trace_id":"x"}` + "\n" }
	code, _, errOut := runCheck(t, checkArgs(stub.srv.URL)...)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errOut, `invalid_scope probe: status 400 body {"error":"invalid_scope","trace_id":"x"}`) {
		t.Errorf("stderr = %q, want body-echo diagnostic", errOut)
	}
}

// TestInvalidScope_EnforcementAbsent drives row 20: a 200 probe response is
// a genuine enforcement-absent failure, body-less by design.
func TestInvalidScope_EnforcementAbsent(t *testing.T) {
	cleanSweepEnv(t)
	stub := newStubCheck(t)
	stub.healthy()
	stub.probeResp = func() (int, string) {
		return http.StatusOK, fmt.Sprintf(`{"access_token":%q}`+"\n", craftJWT(t, map[string]any{"alg": "EdDSA", "typ": "at+jwt", "kid": "testkid"}, map[string]any{"iss": stub.srv.URL}))
	}
	code, _, errOut := runCheck(t, checkArgs(stub.srv.URL)...)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errOut, "invalid_scope not enforced") {
		t.Errorf("stderr = %q, want enforcement-absent diagnostic", errOut)
	}
	if strings.Contains(errOut, "eyJ") {
		t.Errorf("stderr echoes a token from the 200 probe response: %q", errOut)
	}
}

// TestInvalidScope_WrongCode drives row 21.
func TestInvalidScope_WrongCode(t *testing.T) {
	cleanSweepEnv(t)
	stub := newStubCheck(t)
	stub.healthy()
	stub.probeResp = func() (int, string) { return http.StatusBadRequest, `{"error":"invalid_request"}` + "\n" }
	code, _, errOut := runCheck(t, checkArgs(stub.srv.URL)...)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errOut, `invalid_scope probe: error code "invalid_request", expected "invalid_scope"`) {
		t.Errorf("stderr = %q, want wrong-code diagnostic", errOut)
	}
}

// --- A7: T-9 credential-less introspection probe ---

// TestIntrospect_NoCreds401 is the stub green path for T-9.
func TestIntrospect_NoCreds401(t *testing.T) {
	cleanSweepEnv(t)
	stub := newStubCheck(t)
	stub.healthy()
	code, _, errOut := runCheck(t, checkArgs(stub.srv.URL)...)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr:\n%s", code, errOut)
	}
}

// TestIntrospect_NoAuthHeaderLeak pins row 23: with SSO_ADMIN_TOKEN exported,
// the T-9 request carries no Authorization header, and the documented stderr
// notice is emitted.
func TestIntrospect_NoAuthHeaderLeak(t *testing.T) {
	cleanSweepEnv(t)
	t.Setenv(EnvToken, "admin-tok")
	stub := newStubCheck(t)
	stub.healthy()
	code, _, errOut := runCheck(t, checkArgs(stub.srv.URL)...)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr:\n%s", code, errOut)
	}
	if !strings.Contains(errOut, "SSO_ADMIN_TOKEN is set") {
		t.Errorf("stderr = %q, want the admin-token notice", errOut)
	}
	for _, auth := range stub.authHeadersTo("/token/introspect") {
		if auth != "" {
			t.Errorf("T-9 introspect request carried Authorization %q — probe must be credential-less", auth)
		}
	}
}

// TestIntrospect_200Fails / TestIntrospect_400Fails drive row 22: the
// assertion is 401 specifically, with the byte-exact body.
func TestIntrospect_Non401Fails(t *testing.T) {
	cleanSweepEnv(t)
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"status-200", http.StatusOK, `{"active":true}` + "\n", "introspect probe: status 200"},
		{"status-400", http.StatusBadRequest, `{"error":"invalid_request"}` + "\n", "introspect probe: status 400"},
		{"wrong-bytes", http.StatusUnauthorized, `{"error":"invalid_client","trace_id":"x"}` + "\n", `expected 401 {"error":"invalid_client"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := newStubCheck(t)
			stub.healthy()
			status, body := tc.status, tc.body
			stub.t9Resp = func() (int, string) { return status, body }
			code, _, errOut := runCheck(t, checkArgs(stub.srv.URL)...)
			if code != 1 {
				t.Fatalf("exit = %d, want 1", code)
			}
			if !strings.Contains(errOut, tc.want) {
				t.Errorf("stderr = %q, want %q", errOut, tc.want)
			}
		})
	}
}

// TestIntrospect_SkipWhenNotAdvertised pins the skip rule: no advertised
// introspection_endpoint skips T-9 with a stderr notice, never probes the
// canonical path, prints no group line, and forces `check INCOMPLETE` +
// exit 1.
func TestIntrospect_SkipWhenNotAdvertised(t *testing.T) {
	cleanSweepEnv(t)
	stub := newStubCheck(t)
	stub.healthy()
	stub.advertiseDoc(stub.srv.URL, map[string]string{
		"token_endpoint":         "/token",
		"authorization_endpoint": "/auth/login",
		"jwks_uri":               "/jwks",
		"revocation_endpoint":    "/token/revoke",
		"userinfo_endpoint":      "/userinfo",
		"end_session_endpoint":   "/logout",
	})
	code, out, errOut := runCheck(t, checkArgs(stub.srv.URL)...)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.HasSuffix(out, "check INCOMPLETE\n") {
		t.Errorf("stdout = %q, want check INCOMPLETE", out)
	}
	if strings.Contains(out, "introspect:") {
		t.Errorf("stdout = %q, skipped group must print no line", out)
	}
	if strings.Contains(out, "check OK") {
		t.Errorf("stdout = %q, check OK must never print on a skip-run", out)
	}
	if !strings.Contains(errOut, "T-9 skipped") {
		t.Errorf("stderr = %q, want skip notice", errOut)
	}
	if stub.requestsTo("/token/introspect") != 0 {
		t.Error("unadvertised introspection path was probed")
	}
}

// --- security helpers: redaction units + never-echo integration ---

// TestRedactURL_RedactsUserinfo pins the single URL printer: userinfo is
// stripped from URLs and from url.Error-shaped text; non-URL and unparseable
// input passes through unchanged.
func TestRedactURL_RedactsUserinfo(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://user:pass@host/path?q=1", "https://host/path?q=1"},
		{"http://h/x", "http://h/x"},
		{"not a url", "not a url"},
		{"%zz", "%zz"},
		{`Get "http://u:p@h/x": dial tcp: refused`, `Get "http://h/x": dial tcp: refused`},
	}
	for _, tc := range cases {
		if got := redactURL(tc.in); got != tc.want {
			t.Errorf("redactURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestSanitizeBody_RedactsSensitiveFields pins the body printer: sensitive
// JSON values are replaced, other bytes preserved, non-JSON passes through,
// and long bodies truncate with a marker.
func TestSanitizeBody_RedactsSensitiveFields(t *testing.T) {
	in := []byte(`{"error":"x","access_token":"TOK","client_secret":"SEC","refresh_token":"REF","id_token":"IDT","kept":"value"}` + "\n")
	out := string(sanitizeBody(in))
	for _, secret := range []string{"TOK", "SEC", "REF", "IDT"} {
		if strings.Contains(out, secret) {
			t.Errorf("sanitizeBody leaks %q: %q", secret, out)
		}
	}
	for _, frag := range []string{`"access_token":"<redacted>"`, `"client_secret":"<redacted>"`, `"refresh_token":"<redacted>"`, `"id_token":"<redacted>"`, `"kept":"value"`} {
		if !strings.Contains(out, frag) {
			t.Errorf("sanitizeBody output %q missing %q", out, frag)
		}
	}
	plain := sanitizeBody([]byte("plain text body"))
	if string(plain) != "plain text body" {
		t.Errorf("non-JSON body changed: %q", plain)
	}
	long := sanitizeBody([]byte(strings.Repeat("x", 500)))
	if len(long) != bodyEchoLimit+3 || !strings.HasSuffix(string(long), "...") {
		t.Errorf("truncation: len=%d, want %d with marker", len(long), bodyEchoLimit+3)
	}
}

// TestDiagnostics_NeverEchoSecrets is the integration pin: a failing run's
// stderr contains neither the client secret nor a minted-token value, and
// the 200-without-access_token branch prints only the decode error.
func TestDiagnostics_NeverEchoSecrets(t *testing.T) {
	cleanSweepEnv(t)
	stub := newStubCheck(t)
	stub.healthy()
	stub.handle("/token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom","access_token":"MINTED"}` + "\n"))
	})
	code, _, errOut := runCheck(t, "--addr", stub.srv.URL, "--client-id", "demo", "--client-secret", "TOPSECRET")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if strings.Contains(errOut, "TOPSECRET") || strings.Contains(errOut, "MINTED") {
		t.Errorf("stderr leaks a credential: %q", errOut)
	}
	if !strings.Contains(errOut, `"access_token":"<redacted>"`) {
		t.Errorf("stderr = %q, want redacted body echo", errOut)
	}
}

// TestMint_RandReadFailure drives M-8: a crypto/rand failure exits 1 with a
// scope-generation diagnostic and zero probe requests; there is no fallback.
func TestMint_RandReadFailure(t *testing.T) {
	cleanSweepEnv(t)
	stub := newStubCheck(t)
	stub.healthy()
	orig := rand.Reader
	rand.Reader = failingReader{}
	t.Cleanup(func() { rand.Reader = orig })
	code, _, errOut := runCheck(t, checkArgs(stub.srv.URL)...)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errOut, "generate probe scope") {
		t.Errorf("stderr = %q, want scope-generation diagnostic", errOut)
	}
	if stub.requestCount() != 0 {
		t.Errorf("stub received %d requests, want 0 (scope failure precedes any probe)", stub.requestCount())
	}
}

// failingReader is the M-8 crypto/rand failure injection.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, fmt.Errorf("injected rand failure") }
