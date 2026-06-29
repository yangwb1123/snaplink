package extauthz

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/interfaces/sso"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc/codes"
)

// fakeAuthorizer is the test double for the MeshAuthorizer seam (AGENTS.md
// §2: no mocks for storage, but the seam is a pure decision function — a
// fake that records its input and returns a scripted verdict is the right
// tool to test the wire<->seam MAPPING in isolation, with no real
// *sso.Server, token issuer, or Envoy). It records the LAST request it saw
// (so tests assert the CheckRequest was mapped correctly) and returns a
// caller-supplied result (so tests drive ALLOW/DENY without real crypto).
type fakeAuthorizer struct {
	mu      sync.Mutex
	gotReq  sso.MeshAuthorizeRequest
	gotCall int
	result  sso.MeshAuthorizeResult
	// decide, when non-nil, computes the result from the request (so a test
	// can model the seam's sender-constraint decision: deny a bearer that
	// lacks a DPoP proof). When nil, the static result is returned.
	decide func(sso.MeshAuthorizeRequest) sso.MeshAuthorizeResult
}

func (f *fakeAuthorizer) MeshAuthorize(_ context.Context, req sso.MeshAuthorizeRequest) sso.MeshAuthorizeResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotReq = req
	f.gotCall++
	if f.decide != nil {
		return f.decide(req)
	}
	return f.result
}

func (f *fakeAuthorizer) lastRequest() (sso.MeshAuthorizeRequest, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gotReq, f.gotCall
}

// checkRequest builds a minimal Envoy CheckRequest for the given HTTP
// attributes + optional headers. method/scheme/host/path map to the seam's
// Method + reconstructed URL; headers is the lower-cased map Envoy sends.
func checkRequest(method, scheme, host, path string, headers map[string]string) *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method:  method,
					Scheme:  scheme,
					Host:    host,
					Path:    path,
					Headers: headers,
				},
			},
		},
	}
}

// headerOptValue returns the value Envoy would inject for key, and whether
// it was present, from a slice of HeaderValueOption. It also asserts the
// append action is the authoritative OVERWRITE (so an inbound value can
// never be appended to).
func headerOptValue(t *testing.T, opts []*corev3.HeaderValueOption, key string) (string, bool) {
	t.Helper()
	for _, o := range opts {
		if o.GetHeader().GetKey() == key {
			if o.GetAppendAction() != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
				t.Errorf("header %q append action = %v want OVERWRITE_IF_EXISTS_OR_ADD (must not append to inbound)", key, o.GetAppendAction())
			}
			return o.GetHeader().GetValue(), true
		}
	}
	return "", false
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// TestCheck_Allow_InjectsDerivedIdentityAndStripsInbound: an ALLOW verdict
// from the seam produces a CheckResponse OK whose OkHttpResponse injects the
// DERIVED X-Auth-* headers (matching the result's Subject/ClientID/Scopes/
// Expires/Roles in the HTTP handler's exact formats) AND lists every
// X-Auth-* in HeadersToRemove so any client-supplied inbound copy is
// stripped (edge-strip). The inbound CheckRequest deliberately smuggles a
// spoofed X-Auth-Subject; it must NOT appear as the injected value.
func TestCheck_Allow_InjectsDerivedIdentityAndStripsInbound(t *testing.T) {
	t.Parallel()
	exp := time.Now().Add(time.Hour).Unix()
	fake := &fakeAuthorizer{result: sso.MeshAuthorizeResult{
		Allowed:   true,
		Subject:   "user-42",
		ClientID:  "client-abc",
		Scopes:    []string{"openid", "profile"},
		ExpiresAt: exp,
		Roles:     []string{"viewer", "editor"},
	}}
	srv := NewAuthorizationServer(fake)

	// Inbound request carries a SPOOFED X-Auth-Subject the attacker hopes to
	// pass to the upstream. It must be stripped + overridden.
	req := checkRequest("GET", "https", "sso.test", "/mesh/ext-authz", map[string]string{
		"authorization":  "Bearer good-token",
		"x-auth-subject": "attacker-smuggled",
	})

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check returned a Go error (must be nil so DENY can't fail-open): %v", err)
	}
	if got := resp.GetStatus().GetCode(); got != int32(codes.OK) {
		t.Fatalf("status code = %d want %d (OK)", got, int32(codes.OK))
	}
	ok := resp.GetOkResponse()
	if ok == nil {
		t.Fatalf("ALLOW response has no OkHttpResponse (got denied=%v)", resp.GetDeniedResponse())
	}

	// Injected identity matches the seam result, in the HTTP handler's formats.
	if v, present := headerOptValue(t, ok.GetHeaders(), sso.HeaderAuthSubject); !present || v != "user-42" {
		t.Errorf("X-Auth-Subject = %q present=%v want %q (NOT the smuggled value)", v, present, "user-42")
	}
	if v, present := headerOptValue(t, ok.GetHeaders(), sso.HeaderAuthClientID); !present || v != "client-abc" {
		t.Errorf("X-Auth-Client-Id = %q present=%v want %q", v, present, "client-abc")
	}
	if v, present := headerOptValue(t, ok.GetHeaders(), sso.HeaderAuthScopes); !present || v != "openid profile" {
		t.Errorf("X-Auth-Scopes = %q present=%v want space-joined %q", v, present, "openid profile")
	}
	if v, present := headerOptValue(t, ok.GetHeaders(), sso.HeaderAuthExpires); !present || v != strconv.FormatInt(exp, 10) {
		t.Errorf("X-Auth-Expires = %q present=%v want %d", v, present, exp)
	}
	if v, present := headerOptValue(t, ok.GetHeaders(), sso.HeaderAuthRoles); !present || v != "viewer,editor" {
		t.Errorf("X-Auth-Roles = %q present=%v want comma-joined %q", v, present, "viewer,editor")
	}

	// Every X-Auth-* must be in HeadersToRemove (inbound strip / edge-strip).
	for _, h := range []string{sso.HeaderAuthSubject, sso.HeaderAuthClientID, sso.HeaderAuthScopes, sso.HeaderAuthExpires, sso.HeaderAuthRoles} {
		if !contains(ok.GetHeadersToRemove(), h) {
			t.Errorf("HeadersToRemove missing %q — a client-supplied inbound copy would leak to the upstream", h)
		}
	}
}

// TestCheck_Allow_OmitsEmptyOptionalHeaders: optional identity fields that
// are empty/zero on the result are NOT injected (mirrors the HTTP handler,
// which omits empty X-Auth-Client-Id/Scopes/Expires/Roles). Subject is
// always injected on ALLOW.
func TestCheck_Allow_OmitsEmptyOptionalHeaders(t *testing.T) {
	t.Parallel()
	fake := &fakeAuthorizer{result: sso.MeshAuthorizeResult{
		Allowed: true,
		Subject: "only-subject",
		// ClientID/Scopes/ExpiresAt/Roles intentionally zero.
	}}
	srv := NewAuthorizationServer(fake)

	resp, err := srv.Check(context.Background(), checkRequest("GET", "https", "sso.test", "/x", nil))
	if err != nil {
		t.Fatalf("Check error: %v", err)
	}
	ok := resp.GetOkResponse()
	if ok == nil {
		t.Fatalf("no OkHttpResponse")
	}
	if v, present := headerOptValue(t, ok.GetHeaders(), sso.HeaderAuthSubject); !present || v != "only-subject" {
		t.Errorf("X-Auth-Subject = %q present=%v want %q", v, present, "only-subject")
	}
	for _, h := range []string{sso.HeaderAuthClientID, sso.HeaderAuthScopes, sso.HeaderAuthExpires, sso.HeaderAuthRoles} {
		if _, present := headerOptValue(t, ok.GetHeaders(), h); present {
			t.Errorf("%q injected but the result field was empty/zero — must be omitted", h)
		}
	}
	// HeadersToRemove is still the full set regardless (strip all inbound).
	if len(ok.GetHeadersToRemove()) != 5 {
		t.Errorf("HeadersToRemove = %v want all 5 X-Auth-* stripped even when some are omitted", ok.GetHeadersToRemove())
	}
}

// TestCheck_Deny_PermissionDenied401NoBody: a DENY verdict (invalid_token)
// produces a CheckResponse PERMISSION_DENIED + a 401 DeniedHttpResponse with
// the WWW-Authenticate invalid_token challenge, NO body, and NO X-Auth-*
// leaked. The Go error is nil (so the verdict can't fail-open at Envoy).
func TestCheck_Deny_PermissionDenied401NoBody(t *testing.T) {
	t.Parallel()
	fake := &fakeAuthorizer{result: sso.MeshAuthorizeResult{
		Allowed:  false,
		DenyCode: sso.ErrInvalidToken,
	}}
	srv := NewAuthorizationServer(fake)

	resp, err := srv.Check(context.Background(), checkRequest("GET", "https", "sso.test", "/x", map[string]string{
		"authorization": "Bearer bad-token",
	}))
	if err != nil {
		t.Fatalf("Check returned a Go error (DENY must ride in CheckResponse, not a transport error): %v", err)
	}
	if got := resp.GetStatus().GetCode(); got != int32(codes.PermissionDenied) {
		t.Fatalf("status code = %d want %d (PERMISSION_DENIED)", got, int32(codes.PermissionDenied))
	}
	if resp.GetOkResponse() != nil {
		t.Fatalf("DENY response carries an OkHttpResponse — identity must not be present on DENY")
	}
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatalf("no DeniedHttpResponse on DENY")
	}
	if got := denied.GetStatus().GetCode(); got != typev3.StatusCode_Unauthorized {
		t.Errorf("denied HTTP status = %v want 401 Unauthorized", got)
	}
	if denied.GetBody() != "" {
		t.Errorf("denied body = %q want empty (oracle-safe — no per-cause detail)", denied.GetBody())
	}
	// WWW-Authenticate carries the invalid_token challenge.
	wantChallenge := `Bearer realm="sso", error="invalid_token"`
	if v, present := headerOptValue(t, denied.GetHeaders(), "WWW-Authenticate"); !present || v != wantChallenge {
		t.Errorf("WWW-Authenticate = %q present=%v want %q", v, present, wantChallenge)
	}
	// No X-Auth-* may appear anywhere on a DENY.
	for _, h := range []string{sso.HeaderAuthSubject, sso.HeaderAuthClientID, sso.HeaderAuthScopes, sso.HeaderAuthExpires, sso.HeaderAuthRoles} {
		if _, present := headerOptValue(t, denied.GetHeaders(), h); present {
			t.Errorf("DENY leaked identity header %q", h)
		}
	}
}

// TestCheck_Deny_MissingCredentials_BareChallenge: the missing-credentials
// DENY (empty DenyCode) renders a BARE Bearer challenge with no error=
// (RFC 6750 §3.1), matching the seam's missing-vs-invalid distinction and
// the HTTP handler.
func TestCheck_Deny_MissingCredentials_BareChallenge(t *testing.T) {
	t.Parallel()
	fake := &fakeAuthorizer{result: sso.MeshAuthorizeResult{
		Allowed:  false,
		DenyCode: "", // bare-challenge case
	}}
	srv := NewAuthorizationServer(fake)

	resp, err := srv.Check(context.Background(), checkRequest("GET", "https", "sso.test", "/x", nil))
	if err != nil {
		t.Fatalf("Check error: %v", err)
	}
	if resp.GetStatus().GetCode() != int32(codes.PermissionDenied) {
		t.Fatalf("status = %d want PERMISSION_DENIED", resp.GetStatus().GetCode())
	}
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatalf("no DeniedHttpResponse")
	}
	v, present := headerOptValue(t, denied.GetHeaders(), "WWW-Authenticate")
	if !present {
		t.Fatalf("no WWW-Authenticate on DENY")
	}
	if v != `Bearer realm="sso"` {
		t.Errorf("WWW-Authenticate = %q want bare %q (no error= for missing credentials)", v, `Bearer realm="sso"`)
	}
	if strings.Contains(v, "error=") {
		t.Errorf("missing-credentials challenge leaked error= : %q", v)
	}
}

// TestCheck_Deny_DPoPNonceHandshake_SurfacesNonceAndUseDPoPNonce proves the
// gRPC DENY surfaces the RFC 9449 §8/§9 nonce handshake when the seam reports
// one (res.DPoPNonce set): the DeniedHttpResponse carries a DPoP-Nonce header
// with the fresh nonce VALUE AND a WWW-Authenticate challenge whose error is
// use_dpop_nonce (NOT invalid_token), so a mesh-only DPoP client can reissue
// a nonce-bound proof. This is the HIGH fix — without it the fresh nonce
// (which lives only in the seam's unexported challengeHeader) never reaches a
// gRPC-mode DPoP client, permanently breaking it after a nonce expiry. It is
// NOT an oracle leak: the nonce + use_dpop_nonce is the protocol-required
// handshake, exactly what HTTP mode emits.
func TestCheck_Deny_DPoPNonceHandshake_SurfacesNonceAndUseDPoPNonce(t *testing.T) {
	t.Parallel()
	const freshNonce = "fresh-server-nonce-abc123"
	fake := &fakeAuthorizer{result: sso.MeshAuthorizeResult{
		Allowed: false,
		// The seam collapses the HTTP wire code to invalid_token but ALSO sets
		// DPoPNonce on the nonce-required cause; DPoPNonce != "" is the signal.
		DenyCode:  sso.ErrInvalidToken,
		DPoPNonce: freshNonce,
	}}
	srv := NewAuthorizationServer(fake)

	resp, err := srv.Check(context.Background(), checkRequest("GET", "https", "sso.test", "/x", map[string]string{
		"authorization": "Bearer dpop-bound-token",
		"dpop":          "proof-without-a-nonce",
	}))
	if err != nil {
		t.Fatalf("Check returned a Go error: %v", err)
	}
	if resp.GetStatus().GetCode() != int32(codes.PermissionDenied) {
		t.Fatalf("status = %d want PERMISSION_DENIED (still a DENY)", resp.GetStatus().GetCode())
	}
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatalf("no DeniedHttpResponse")
	}
	if denied.GetStatus().GetCode() != typev3.StatusCode_Unauthorized {
		t.Errorf("denied HTTP status = %v want 401", denied.GetStatus().GetCode())
	}
	if denied.GetBody() != "" {
		t.Errorf("denied body = %q want empty (oracle-safe)", denied.GetBody())
	}
	// The fresh nonce is surfaced as a DPoP-Nonce header carrying the VALUE.
	if v, present := headerOptValue(t, denied.GetHeaders(), sso.HeaderDPoPNonce); !present || v != freshNonce {
		t.Errorf("DPoP-Nonce = %q present=%v want %q (the fresh nonce the client reissues with)", v, present, freshNonce)
	}
	// The challenge error is use_dpop_nonce (the handshake), NOT invalid_token.
	wantChallenge := `Bearer realm="sso", error="use_dpop_nonce"`
	if v, present := headerOptValue(t, denied.GetHeaders(), "WWW-Authenticate"); !present || v != wantChallenge {
		t.Errorf("WWW-Authenticate = %q present=%v want %q", v, present, wantChallenge)
	}
	// No identity leaks on the handshake DENY either.
	for _, h := range []string{sso.HeaderAuthSubject, sso.HeaderAuthClientID, sso.HeaderAuthScopes, sso.HeaderAuthExpires, sso.HeaderAuthRoles} {
		if _, present := headerOptValue(t, denied.GetHeaders(), h); present {
			t.Errorf("nonce-handshake DENY leaked identity header %q", h)
		}
	}
}

// TestCheck_Deny_InvalidToken_NoDPoPNonceHeader proves the contrapositive:
// an ordinary invalid_token DENY (res.DPoPNonce empty — every NON-nonce
// cause) carries NO DPoP-Nonce header and keeps the invalid_token challenge.
// This locks the oracle-safety boundary: only the genuine nonce handshake
// gets the nonce signal; binding/validity/residency stay non-probeable.
func TestCheck_Deny_InvalidToken_NoDPoPNonceHeader(t *testing.T) {
	t.Parallel()
	fake := &fakeAuthorizer{result: sso.MeshAuthorizeResult{
		Allowed:  false,
		DenyCode: sso.ErrInvalidToken,
		// DPoPNonce intentionally empty — not the handshake case.
	}}
	srv := NewAuthorizationServer(fake)

	resp, err := srv.Check(context.Background(), checkRequest("GET", "https", "sso.test", "/x", map[string]string{
		"authorization": "Bearer bad-token",
	}))
	if err != nil {
		t.Fatalf("Check error: %v", err)
	}
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatalf("no DeniedHttpResponse")
	}
	// No DPoP-Nonce header on a non-handshake DENY.
	if v, present := headerOptValue(t, denied.GetHeaders(), sso.HeaderDPoPNonce); present {
		t.Errorf("DPoP-Nonce = %q present on a plain invalid_token DENY — must be absent (oracle-safe)", v)
	}
	// Challenge stays invalid_token, NOT use_dpop_nonce.
	wantChallenge := `Bearer realm="sso", error="invalid_token"`
	if v, present := headerOptValue(t, denied.GetHeaders(), "WWW-Authenticate"); !present || v != wantChallenge {
		t.Errorf("WWW-Authenticate = %q present=%v want %q", v, present, wantChallenge)
	}
}

// TestCheck_RequestMapping_MethodURLHeadersReachSeam: the CheckRequest's
// Method, scheme/host/path (-> reconstructed URL), and headers all reach the
// MeshAuthorizeRequest the seam sees. Asserted via the fake recording its
// input — this is the load-bearing mapping (the seam can only enforce the
// DPoP htm/htu + bearer if it receives them faithfully).
func TestCheck_RequestMapping_MethodURLHeadersReachSeam(t *testing.T) {
	t.Parallel()
	fake := &fakeAuthorizer{result: sso.MeshAuthorizeResult{Allowed: true, Subject: "s"}}
	srv := NewAuthorizationServer(fake)

	headers := map[string]string{
		"authorization":     "Bearer the-token",
		"dpop":              "the-dpop-proof",
		"x-forwarded-proto": "https",
		"x-forwarded-host":  "public.example",
	}
	_, err := srv.Check(context.Background(), checkRequest("POST", "https", "sso.test", "/mesh/ext-authz", headers))
	if err != nil {
		t.Fatalf("Check error: %v", err)
	}

	got, calls := fake.lastRequest()
	if calls != 1 {
		t.Fatalf("MeshAuthorize called %d times want 1", calls)
	}
	if got.Method != "POST" {
		t.Errorf("seam Method = %q want POST", got.Method)
	}
	if got.URL != "https://sso.test/mesh/ext-authz" {
		t.Errorf("seam URL = %q want reconstructed %q", got.URL, "https://sso.test/mesh/ext-authz")
	}
	// Headers must be a canonical http.Header the stdlib readers can use:
	// the bearer under "Authorization", the proof retrievable via Get("DPoP"),
	// the X-Forwarded-* chain under canonical keys.
	if got.Header.Get("Authorization") != "Bearer the-token" {
		t.Errorf("seam Authorization = %q want %q", got.Header.Get("Authorization"), "Bearer the-token")
	}
	if got.Header.Get("DPoP") != "the-dpop-proof" {
		t.Errorf("seam DPoP (via canonical Get) = %q want %q", got.Header.Get("DPoP"), "the-dpop-proof")
	}
	if got.Header.Get("X-Forwarded-Proto") != "https" || got.Header.Get("X-Forwarded-Host") != "public.example" {
		t.Errorf("seam X-Forwarded-* not mapped: proto=%q host=%q", got.Header.Get("X-Forwarded-Proto"), got.Header.Get("X-Forwarded-Host"))
	}
}

// TestCheck_RequestMapping_URLWithQueryInPath is the PRODUCTION shape: Envoy
// embeds the query INSIDE GetPath() (`/path?a=1&b=2`) and leaves GetQuery()
// EMPTY (the ext_authz AttributeContext never splits the query out). The
// reconstructed URL must carry the query as a real RawQuery — NOT percent-
// encode the '?' into the path (`/path%3Fa=1`, which the old code produced).
// We assert via url.Parse that Path and RawQuery come back distinct, and that
// the seam's htu normalization would still see the bare path.
func TestCheck_RequestMapping_URLWithQueryInPath(t *testing.T) {
	t.Parallel()
	fake := &fakeAuthorizer{result: sso.MeshAuthorizeResult{Allowed: true, Subject: "s"}}
	srv := NewAuthorizationServer(fake)

	// Production shape: query lives in Path; GetQuery() is empty.
	req := checkRequest("GET", "https", "api.example", "/mesh/ext-authz?a=1&b=2", nil)
	if _, err := srv.Check(context.Background(), req); err != nil {
		t.Fatalf("Check error: %v", err)
	}
	got, _ := fake.lastRequest()
	if got.URL != "https://api.example/mesh/ext-authz?a=1&b=2" {
		t.Fatalf("seam URL = %q want %q (query split out of path, NOT %%3F-encoded)", got.URL, "https://api.example/mesh/ext-authz?a=1&b=2")
	}
	// The '?' must NOT have been percent-encoded into the path.
	if strings.Contains(got.URL, "%3F") || strings.Contains(got.URL, "%3f") {
		t.Errorf("seam URL = %q percent-encoded the '?' into the path (the bug)", got.URL)
	}
	// Parse the reconstructed URL the way the seam's neturl.Parse does and
	// confirm Path/RawQuery are distinct — so r.URL.Path is the bare path the
	// htu binding (after normalizeDPoPHTU) and the base-URL path rely on.
	u, err := url.Parse(got.URL)
	if err != nil {
		t.Fatalf("reconstructed URL did not parse: %v", err)
	}
	if u.Path != "/mesh/ext-authz" {
		t.Errorf("parsed Path = %q want %q (must not contain the query)", u.Path, "/mesh/ext-authz")
	}
	if u.RawQuery != "a=1&b=2" {
		t.Errorf("parsed RawQuery = %q want %q", u.RawQuery, "a=1&b=2")
	}
}

// TestCheck_RequestMapping_QueryFallbackFromGetQuery is the DEFENSIVE path:
// Envoy's documented behavior puts the query in GetPath(), but a non-
// conformant data plane might populate GetQuery() instead with a bare path.
// The fallback still carries the query (we never silently drop it), and the
// scheme defaults to https when omitted.
func TestCheck_RequestMapping_QueryFallbackFromGetQuery(t *testing.T) {
	t.Parallel()
	fake := &fakeAuthorizer{result: sso.MeshAuthorizeResult{Allowed: true, Subject: "s"}}
	srv := NewAuthorizationServer(fake)

	req := checkRequest("GET", "", "api.example", "/v1/resource", nil) // empty scheme, no '?' in path
	req.GetAttributes().GetRequest().GetHttp().Query = "a=1&b=2"       // query only in GetQuery()
	if _, err := srv.Check(context.Background(), req); err != nil {
		t.Fatalf("Check error: %v", err)
	}
	got, _ := fake.lastRequest()
	if got.URL != "https://api.example/v1/resource?a=1&b=2" {
		t.Errorf("seam URL = %q want %q (scheme defaulted https, query from GetQuery fallback)", got.URL, "https://api.example/v1/resource?a=1&b=2")
	}
}

// TestCheck_ClientCertParsedAndPassed: when the CheckRequest carries a peer
// certificate in Source.Certificate (Envoy's URL-encoded PEM), Check parses
// it to an *x509.Certificate and passes it on the MeshAuthorizeRequest, so
// the seam can enforce an mTLS sender-constraint. Verified via the fake
// recording the cert.
func TestCheck_ClientCertParsedAndPassed(t *testing.T) {
	t.Parallel()
	leaf, pemBytes := makeTestCert(t)

	fake := &fakeAuthorizer{result: sso.MeshAuthorizeResult{Allowed: true, Subject: "s"}}
	srv := NewAuthorizationServer(fake)

	req := checkRequest("GET", "https", "sso.test", "/x", map[string]string{"authorization": "Bearer t"})
	// Envoy URL-encodes the PEM in Source.Certificate.
	req.GetAttributes().Source = &authv3.AttributeContext_Peer{
		Certificate: url.QueryEscape(string(pemBytes)),
	}

	if _, err := srv.Check(context.Background(), req); err != nil {
		t.Fatalf("Check error: %v", err)
	}
	got, _ := fake.lastRequest()
	if got.ClientCert == nil {
		t.Fatalf("seam ClientCert = nil want the parsed peer cert")
	}
	if got.ClientCert.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Errorf("seam ClientCert serial = %v want %v (wrong cert parsed)", got.ClientCert.SerialNumber, leaf.SerialNumber)
	}
	if !got.ClientCert.Equal(leaf) {
		t.Errorf("seam ClientCert is not byte-equal to the source cert")
	}
}

// TestCheck_ClientCert_RawPEM_NotURLEncoded: a tolerant fallback — some
// Envoy builds may forward un-escaped PEM. The parser must still decode it
// (QueryUnescape is a no-op on text without '%').
func TestCheck_ClientCert_RawPEM_NotURLEncoded(t *testing.T) {
	t.Parallel()
	leaf, pemBytes := makeTestCert(t)
	fake := &fakeAuthorizer{result: sso.MeshAuthorizeResult{Allowed: true, Subject: "s"}}
	srv := NewAuthorizationServer(fake)

	req := checkRequest("GET", "https", "sso.test", "/x", nil)
	req.GetAttributes().Source = &authv3.AttributeContext_Peer{Certificate: string(pemBytes)} // raw PEM
	if _, err := srv.Check(context.Background(), req); err != nil {
		t.Fatalf("Check error: %v", err)
	}
	got, _ := fake.lastRequest()
	if got.ClientCert == nil || !got.ClientCert.Equal(leaf) {
		t.Errorf("raw-PEM peer cert not parsed/passed: %v", got.ClientCert)
	}
}

// TestCheck_NoClientCert_NilOnSeam: no Source.Certificate -> ClientCert is
// nil on the seam request (the seam treats it as "no mTLS material").
func TestCheck_NoClientCert_NilOnSeam(t *testing.T) {
	t.Parallel()
	fake := &fakeAuthorizer{result: sso.MeshAuthorizeResult{Allowed: true, Subject: "s"}}
	srv := NewAuthorizationServer(fake)
	if _, err := srv.Check(context.Background(), checkRequest("GET", "https", "sso.test", "/x", nil)); err != nil {
		t.Fatalf("Check error: %v", err)
	}
	if got, _ := fake.lastRequest(); got.ClientCert != nil {
		t.Errorf("ClientCert = %v want nil (no Source.Certificate)", got.ClientCert)
	}
}

// TestCheck_MalformedClientCert_NilNotError: a garbage Source.Certificate
// must NOT crash or error — it yields a nil ClientCert (fail-safe: a bad
// cert can only fail an mTLS sender-constraint, never satisfy one). The
// request still flows to the seam, which decides.
func TestCheck_MalformedClientCert_NilNotError(t *testing.T) {
	t.Parallel()
	fake := &fakeAuthorizer{result: sso.MeshAuthorizeResult{Allowed: false, DenyCode: sso.ErrInvalidToken}}
	srv := NewAuthorizationServer(fake)

	req := checkRequest("GET", "https", "sso.test", "/x", map[string]string{"authorization": "Bearer t"})
	req.GetAttributes().Source = &authv3.AttributeContext_Peer{Certificate: "%%%-not-a-cert-%%%"}
	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check errored on a malformed cert (must be tolerant): %v", err)
	}
	if got, _ := fake.lastRequest(); got.ClientCert != nil {
		t.Errorf("ClientCert = %v want nil for a malformed certificate", got.ClientCert)
	}
	// And the verdict still comes from the seam.
	if resp.GetStatus().GetCode() != int32(codes.PermissionDenied) {
		t.Errorf("status = %d want PERMISSION_DENIED (seam denied)", resp.GetStatus().GetCode())
	}
}

// TestCheck_SenderConstraint_DPoPBoundAsPlainBearer_Denies models the
// sender-constraint through the seam: the fake denies (invalid_token) any
// request whose bearer looks DPoP-bound but carries no DPoP proof header —
// exactly the decision the real seam makes. The test's job is to confirm
// Check PASSES the inputs that let the seam decide (the bearer + the absence
// of a proof) and faithfully surfaces the resulting DENY. A stolen
// sender-constrained token therefore cannot replay as a plain bearer over
// gRPC.
func TestCheck_SenderConstraint_DPoPBoundAsPlainBearer_Denies(t *testing.T) {
	t.Parallel()
	fake := &fakeAuthorizer{decide: func(req sso.MeshAuthorizeRequest) sso.MeshAuthorizeResult {
		// Model the seam: a DPoP-bound token WITHOUT a proof is denied.
		hasBearer := req.Header.Get("Authorization") == "Bearer dpop-bound-token"
		hasProof := req.Header.Get("DPoP") != ""
		if hasBearer && !hasProof {
			return sso.MeshAuthorizeResult{Allowed: false, DenyCode: sso.ErrInvalidToken}
		}
		return sso.MeshAuthorizeResult{Allowed: true, Subject: "s"}
	}}
	srv := NewAuthorizationServer(fake)

	// Replay attempt: the DPoP-bound token presented as a plain bearer (no
	// DPoP header).
	resp, err := srv.Check(context.Background(), checkRequest("GET", "https", "sso.test", "/x", map[string]string{
		"authorization": "Bearer dpop-bound-token",
	}))
	if err != nil {
		t.Fatalf("Check error: %v", err)
	}
	if resp.GetStatus().GetCode() != int32(codes.PermissionDenied) {
		t.Fatalf("status = %d want PERMISSION_DENIED (DPoP-bound token replayed as plain bearer must DENY)", resp.GetStatus().GetCode())
	}
	if resp.GetOkResponse() != nil {
		t.Errorf("identity present on a sender-constraint DENY")
	}

	// Control: present a proof -> the seam (fake) allows, proving the deny
	// above was the missing proof, not an unrelated rejection, and that the
	// proof header reaches the seam.
	respOK, err := srv.Check(context.Background(), checkRequest("GET", "https", "sso.test", "/x", map[string]string{
		"authorization": "Bearer dpop-bound-token",
		"dpop":          "a-proof",
	}))
	if err != nil {
		t.Fatalf("Check error: %v", err)
	}
	if respOK.GetStatus().GetCode() != int32(codes.OK) {
		t.Errorf("control status = %d want OK (proof present)", respOK.GetStatus().GetCode())
	}
}

// makeTestCert builds a throwaway self-signed ECDSA certificate and returns
// the parsed *x509.Certificate plus its PEM encoding (the form Envoy
// URL-encodes into Source.Certificate).
func makeTestCert(t *testing.T) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "mesh-client.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return leaf, pemBytes
}
