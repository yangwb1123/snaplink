package ssotest

// trusted_proxy_gate_test.go proves the security.trusted_proxies peer gate
// end-to-end over real HTTP (the direct peer is the httptest loopback
// 127.0.0.1, trusted or not depending on the configured CIDRs):
//
//   - mesh ext_authz serves identity ONLY to a trusted direct peer, and the
//     untrusted DENY is byte-shaped like an invalid bearer (oracle-safe);
//   - the mTLS header-cert extractor ignores a peer-forged cert header, and
//     the resulting /userinfo rejection is byte-identical to the plain
//     missing-cert invalid_token challenge (no new oracle);
//   - issuer/base-URL derivation ignores X-Forwarded-Proto/Host from an
//     untrusted peer;
//   - with the knob UNSET every path keeps the legacy first-hop trust.

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/security"
	"github.com/yangwb1123/snaplink/shared/security/peertrust"
)

const (
	tpgClient = "tpg-client"
	tpgSecret = "tpg-secret"
	tpgUser   = "u-tpg"
)

// newPeerTrustHarness stands up a minimal password+jwt server (same shape as
// the mtls harness) with the caller's extra options appended.
func newPeerTrustHarness(t *testing.T, extra ...sso.Option) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: tpgUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: tpgClient, Secret: tpgSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != "pw" {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: tpgUser, Provider: "password"}, nil
		},
	))
	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
	}
	opts = append(opts, extra...)
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func tpgTrustedProxiesOpt(t *testing.T, cidrs ...string) sso.Option {
	t.Helper()
	opt, err := sso.WithTrustedProxies(cidrs, 0)
	if err != nil {
		t.Fatalf("WithTrustedProxies(%v): %v", cidrs, err)
	}
	return opt
}

func tpgChecker(t *testing.T, cidrs ...string) *peertrust.Checker {
	t.Helper()
	c, err := peertrust.NewChecker(cidrs)
	if err != nil {
		t.Fatalf("NewChecker(%v): %v", cidrs, err)
	}
	return c
}

// genSelfSignedCertPEM PEM-encodes a fresh self-signed cert (reusing the
// mtls harness generator) for the forwarded-cert header.
func genSelfSignedCertPEM(t *testing.T) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: loadTestCert(t).Raw}))
}

// tpgMintToken mints a client_credentials access token, optionally with a
// forwarded client-cert header attached to the /token request.
func tpgMintToken(t *testing.T, srv *httptest.Server, certHeader map[string]string) string {
	t.Helper()
	form := "grant_type=client_credentials&client_id=" + tpgClient + "&client_secret=" + tpgSecret
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/token", strings.NewReader(form))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range certHeader {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token status=%d body=%s", resp.StatusCode, rb)
	}
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	access, _ := out["access_token"].(string)
	if access == "" {
		t.Fatalf("no access_token in %s", rb)
	}
	return access
}

func tpgGet(t *testing.T, rawURL, bearer string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// --- mesh ext_authz ---------------------------------------------------------

func TestTrustedProxyGate_Mesh_UntrustedPeerDenied(t *testing.T) {
	t.Parallel()
	srv := newPeerTrustHarness(t,
		sso.WithMeshExtAuthz("/mesh/ext-authz"),
		tpgTrustedProxiesOpt(t, "10.0.0.0/8"), // loopback peer NOT trusted
	)
	access := tpgMintToken(t, srv, nil)

	resp := tpgGet(t, srv.URL+"/mesh/ext-authz", access, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("untrusted peer mesh status=%d, want 401", resp.StatusCode)
	}
	// Oracle shape: same challenge as an invalid bearer, and no identity.
	if www := resp.Header.Get("WWW-Authenticate"); !strings.Contains(www, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate = %q, want invalid_token challenge", www)
	}
	if sub := resp.Header.Get("X-Auth-Subject"); sub != "" {
		t.Errorf("X-Auth-Subject leaked on untrusted peer: %q", sub)
	}
	if cid := resp.Header.Get("X-Auth-Client-Id"); cid != "" {
		t.Errorf("X-Auth-Client-Id leaked on untrusted peer: %q", cid)
	}
}

func TestTrustedProxyGate_Mesh_TrustedPeerAllowed(t *testing.T) {
	t.Parallel()
	srv := newPeerTrustHarness(t,
		sso.WithMeshExtAuthz("/mesh/ext-authz"),
		tpgTrustedProxiesOpt(t, "127.0.0.0/8"), // loopback peer IS trusted
	)
	access := tpgMintToken(t, srv, nil)

	resp := tpgGet(t, srv.URL+"/mesh/ext-authz", access, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("trusted peer mesh status=%d, want 200", resp.StatusCode)
	}
	if cid := resp.Header.Get("X-Auth-Client-Id"); cid != tpgClient {
		t.Errorf("X-Auth-Client-Id = %q, want %q", cid, tpgClient)
	}
}

func TestTrustedProxyGate_Mesh_UnsetKnobKeepsLegacyBehavior(t *testing.T) {
	t.Parallel()
	srv := newPeerTrustHarness(t, sso.WithMeshExtAuthz("/mesh/ext-authz"))
	access := tpgMintToken(t, srv, nil)

	resp := tpgGet(t, srv.URL+"/mesh/ext-authz", access, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unset knob mesh status=%d, want 200 (legacy)", resp.StatusCode)
	}
}

// --- mTLS header-cert extractor ----------------------------------------------

func TestTrustedProxyGate_MTLSHeader_OracleShapePreserved(t *testing.T) {
	t.Parallel()
	ext := security.NewHeaderClientCertExtractor("X-SSL-Client-Cert")
	srv := newPeerTrustHarness(t, sso.WithClientCertExtractor(ext))

	certPEM := genSelfSignedCertPEM(t)
	certHeader := map[string]string{"X-SSL-Client-Cert": url.QueryEscape(certPEM)}

	// Phase 1 (PeerTrust unset): mint a BOUND token via the cert header.
	access := tpgMintToken(t, srv, certHeader)
	payload := decodeAccessTokenPayload(t, access)
	if _, ok := payload["cnf"].(map[string]any); !ok {
		t.Fatalf("expected cnf on token minted with cert header, got %v", payload)
	}

	// Phase 2: gate the extractor on a CIDR excluding the loopback peer.
	// The peer-forged cert header must now yield "no cert", so the bound
	// token collapses to the NORMAL missing-cert rejection.
	ext.PeerTrust = tpgChecker(t, "10.0.0.0/8")
	gated := tpgGet(t, srv.URL+"/userinfo", access, certHeader)
	if gated.StatusCode != http.StatusUnauthorized {
		t.Fatalf("untrusted peer /userinfo status=%d, want 401", gated.StatusCode)
	}
	gatedWWW := gated.Header.Get("WWW-Authenticate")

	// Phase 3 (oracle comparison): the same request with NO cert header and
	// NO gate produces the missing-cert challenge — the gated rejection must
	// be byte-identical so the gate's existence is not probeable.
	ext.PeerTrust = nil
	missing := tpgGet(t, srv.URL+"/userinfo", access, nil)
	if missing.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing-cert /userinfo status=%d, want 401", missing.StatusCode)
	}
	if missingWWW := missing.Header.Get("WWW-Authenticate"); gatedWWW != missingWWW {
		t.Errorf("gated challenge %q != missing-cert challenge %q (oracle leak)", gatedWWW, missingWWW)
	}
	if !strings.Contains(gatedWWW, `error="invalid_token"`) {
		t.Errorf("gated challenge = %q, want invalid_token shape", gatedWWW)
	}
}

func TestTrustedProxyGate_MTLSHeader_UntrustedPeerMintsUnboundToken(t *testing.T) {
	t.Parallel()
	ext := security.NewHeaderClientCertExtractor("X-SSL-Client-Cert")
	ext.PeerTrust = tpgChecker(t, "10.0.0.0/8") // loopback peer NOT trusted
	srv := newPeerTrustHarness(t, sso.WithClientCertExtractor(ext))

	certHeader := map[string]string{"X-SSL-Client-Cert": url.QueryEscape(genSelfSignedCertPEM(t))}
	access := tpgMintToken(t, srv, certHeader)
	payload := decodeAccessTokenPayload(t, access)
	// Same wire outcome as presenting no cert: an UNBOUND bearer.
	if cnf, ok := payload["cnf"]; ok {
		t.Errorf("cnf unexpectedly present on peer-forged cert header: %v", cnf)
	}
}

// --- issuer / base-URL --------------------------------------------------------

func TestTrustedProxyGate_Discovery_UntrustedPeerIgnoresForwardedHost(t *testing.T) {
	t.Parallel()
	srv := newPeerTrustHarness(t, tpgTrustedProxiesOpt(t, "10.0.0.0/8"))

	resp := tpgGet(t, srv.URL+"/.well-known/openid-configuration", "", map[string]string{
		"X-Forwarded-Proto": "https",
		"X-Forwarded-Host":  "evil.example",
	})
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	issuer, _ := doc["issuer"].(string)
	if issuer != srv.URL {
		t.Errorf("issuer = %q, want %q (forwarded headers from untrusted peer must be ignored)", issuer, srv.URL)
	}
}

func TestTrustedProxyGate_Discovery_UnsetKnobHonorsForwardedHost(t *testing.T) {
	t.Parallel()
	srv := newPeerTrustHarness(t)

	resp := tpgGet(t, srv.URL+"/.well-known/openid-configuration", "", map[string]string{
		"X-Forwarded-Proto": "https",
		"X-Forwarded-Host":  "public.example.com",
	})
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	issuer, _ := doc["issuer"].(string)
	if issuer != "https://public.example.com" {
		t.Errorf("issuer = %q, want https://public.example.com (legacy first-hop trust)", issuer)
	}
}

func TestTrustedProxyGate_Discovery_TrustedPeerHonorsForwardedHost(t *testing.T) {
	t.Parallel()
	srv := newPeerTrustHarness(t, tpgTrustedProxiesOpt(t, "127.0.0.0/8"))

	resp := tpgGet(t, srv.URL+"/.well-known/openid-configuration", "", map[string]string{
		"X-Forwarded-Proto": "https",
		"X-Forwarded-Host":  "public.example.com",
	})
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	issuer, _ := doc["issuer"].(string)
	if issuer != "https://public.example.com" {
		t.Errorf("issuer = %q, want https://public.example.com (trusted edge)", issuer)
	}
}
