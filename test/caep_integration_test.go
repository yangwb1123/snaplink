package ssotest

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/caep"
	"github.com/snaplink/sso/defaultimpl"
)

// This is the FULL-SERVER companion to caep/transmitter_test.go: that suite
// drives Transmitter.Record directly, proving the mint+scope+POST logic; this
// one proves the AUDIT-PIPELINE WIRING — that a real revocation event flowing
// through a real *sso.Server (audit recorder tapped by WithCAEPTransmitter)
// reaches the transmitter and delivers a scoped, JWKS-verifiable SET. It also
// re-proves the cross-tenant-no-leak crux at the full-server level: a client in
// a DIFFERENT tenant with its own receiver gets NOTHING.

const (
	caepTenantT  = "tenant-T"
	caepTenantD  = "tenant-OTHER"
	caepClientC  = "caep-client-c"
	caepClientD  = "caep-client-d"
	caepIssuer   = "https://idp.caep.test"
	caepRPCSecre = "Bearer rp-c-secret"
)

// caepReceived captures one delivered SET + the request that carried it.
type caepReceived struct {
	authHeader  string
	contentType string
	token       string
}

// caepReceiver is an httptest SET receiver that records every POST it accepts.
type caepReceiver struct {
	mu   sync.Mutex
	sets []caepReceived
}

func (r *caepReceiver) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.sets = append(r.sets, caepReceived{
			authHeader:  req.Header.Get("Authorization"),
			contentType: req.Header.Get("Content-Type"),
			token:       string(body),
		})
		r.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}
}

func (r *caepReceiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sets)
}

func (r *caepReceiver) snapshot() []caepReceived {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]caepReceived(nil), r.sets...)
}

// caepTrustClient returns an http.Client that trusts exactly the supplied
// httptest TLS servers' certs (NOT skip-verify) — the transmitter still does
// real TLS verification, and receivers MUST be https per the anti-exfil rule.
func caepTrustClient(servers ...*httptest.Server) *http.Client {
	pool := x509.NewCertPool()
	for _, s := range servers {
		pool.AddCert(s.Certificate())
	}
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}
}

// caepPubKeyFromJWKS resolves the Ed25519 public key for kid from the server's
// JWKS — proving the SET validates against the PUBLISHED key set (no new RP
// trust setup), not merely against a key the test happens to hold.
func caepPubKeyFromJWKS(t *testing.T, iss *defaultimpl.Ed25519JWTIssuer, kid string) ed25519.PublicKey {
	t.Helper()
	jwks, err := iss.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	for _, jwk := range jwks {
		if jwk.Kid != kid {
			continue
		}
		if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
			t.Fatalf("JWKS kid %q is not an Ed25519 OKP key: kty=%q crv=%q", kid, jwk.Kty, jwk.Crv)
		}
		raw, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			t.Fatalf("decode JWKS x for kid %q: %v", kid, err)
		}
		return ed25519.PublicKey(raw)
	}
	t.Fatalf("kid %q not found in server JWKS", kid)
	return nil
}

// caepVerifiedSET is a decoded + JWKS-signature-verified SET.
type caepVerifiedSET struct {
	typ    string
	iss    string
	jti    string
	aud    []string
	subID  map[string]any
	events map[string]json.RawMessage
}

// caepVerifySET decodes a compact-JWS SET, resolves its kid against the
// server's JWKS, and verifies the signature against that published key. A
// failed signature fails the test — proving the SET is minted by the trusted
// JWKS key.
func caepVerifySET(t *testing.T, token string, iss *defaultimpl.Ed25519JWTIssuer) caepVerifiedSET {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("SET is not a 3-part compact JWS: %q", token)
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		t.Fatalf("parse header: %v", err)
	}
	pub := caepPubKeyFromJWKS(t, iss, hdr.Kid)
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("SET signature does not verify against the server JWKS key")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var p struct {
		Iss    string                     `json:"iss"`
		Jti    string                     `json:"jti"`
		Aud    []string                   `json:"aud"`
		SubID  map[string]any             `json:"sub_id"`
		Events map[string]json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(pb, &p); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	return caepVerifiedSET{typ: hdr.Typ, iss: p.Iss, jti: p.Jti, aud: p.Aud, subID: p.SubID, events: p.Events}
}

// caepWaitFor polls cond until true or a 3s deadline, failing on timeout —
// awaits the async SET delivery without a fixed sleep.
func caepWaitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

// TestCAEP_FullServer_TenantRevokeDeliversScopedSET wires a real *sso.Server
// with WithCAEPTransmitter + a real Ed25519 issuer, registers client C (tenant
// T) and client D (a DIFFERENT tenant), each with its own https receiver, then
// drives a REAL tenant-tokens-revoked event through the server's audit pipeline
// via RevokeTenantRefreshTokens. It asserts:
//   - C's receiver got exactly ONE POST carrying a JWKS-verifiable SET with
//     typ=secevent+jwt, the right SSF event URIs, iss = the server issuer, and
//     aud = [C.ID].
//   - D's receiver (different tenant) got NOTHING — the cross-tenant-no-leak
//     guarantee, now proven end-to-end through the full server.
func TestCAEP_FullServer_TenantRevokeDeliversScopedSET(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	recvC := &caepReceiver{}
	srvC := httptest.NewTLSServer(recvC.handler())
	defer srvC.Close()
	recvD := &caepReceiver{}
	srvD := httptest.NewTLSServer(recvD.handler())
	defer srvD.Close()

	// Real Ed25519 issuer: the SAME key that mints tokens + populates JWKS
	// signs the SET, so an RP validates it against the published key set.
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(caepIssuer))

	// Memory client store doubles as the receiver source AND the
	// TenantScopedClientStore the tenant fan-out resolves through.
	clients := defaultimpl.NewMemoryClientStore()
	if err := clients.Add(ctx, &sso.Client{
		ID: caepClientC, TenantID: caepTenantT, Active: true,
		Attributes: map[string]string{
			caep.AttrReceiverEndpoint: srvC.URL,
			caep.AttrReceiverAuth:     caepRPCSecre,
		},
	}); err != nil {
		t.Fatalf("add client C: %v", err)
	}
	if err := clients.Add(ctx, &sso.Client{
		ID: caepClientD, TenantID: caepTenantD, Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: srvD.URL},
	}); err != nil {
		t.Fatalf("add client D: %v", err)
	}

	// Real refresh-token store: it is the RefreshTokenClientPurger
	// RevokeTenantRefreshTokens drives, so the tenant-tokens-revoked audit
	// event fires through the real path (not a hand-built event).
	refresh := defaultimpl.NewMemoryRefreshTokenStore()

	rec := audit.New(audit.NewMemorySink(16))

	// The transmitter is wired through the real server option. It trusts only
	// the two httptest TLS receivers (real TLS verification preserved).
	tx := caep.NewTransmitter(iss, clients,
		caep.WithIssuer(caepIssuer),
		caep.WithHTTPClient(caepTrustClient(srvC, srvD)))

	srv := sso.NewServer(
		sso.WithClientStore(clients),
		sso.WithRefreshTokenStore(refresh, time.Hour),
		sso.WithTokenIssuer("jwt", iss),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuditRecorder(rec),
		sso.WithCAEPTransmitter(tx),
	)

	// Drive the REAL revocation path: this purges tenant-T clients' refresh
	// tokens and emits tenant_tokens_revoked through the audit recorder the
	// server tapped for the transmitter.
	if _, err := srv.RevokeTenantRefreshTokens(ctx, caepTenantT); err != nil {
		t.Fatalf("RevokeTenantRefreshTokens: %v", err)
	}

	caepWaitFor(t, func() bool { return recvC.count() == 1 }, "client C receives one SET")
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("transmitter close: %v", err)
	}

	// Cross-tenant-no-leak crux: D (a DIFFERENT tenant) must have received
	// nothing for a tenant-T event.
	if got := recvD.count(); got != 0 {
		t.Fatalf("cross-tenant leak: client D in %s received %d SET(s) for a %s event", caepTenantD, got, caepTenantT)
	}
	if got := recvC.count(); got != 1 {
		t.Fatalf("client C want exactly 1 SET, got %d", got)
	}

	got := recvC.snapshot()[0]
	if got.contentType != "application/secevent+jwt" {
		t.Errorf("content-type = %q, want application/secevent+jwt", got.contentType)
	}
	if got.authHeader != caepRPCSecre {
		t.Errorf("authorization = %q, want the client's registered auth %q", got.authHeader, caepRPCSecre)
	}
	v := caepVerifySET(t, got.token, iss)
	if v.typ != caep.SecurityEventTokenTyp {
		t.Errorf("typ = %q, want %q", v.typ, caep.SecurityEventTokenTyp)
	}
	if v.iss != caepIssuer {
		t.Errorf("iss = %q, want %q", v.iss, caepIssuer)
	}
	if len(v.aud) != 1 || v.aud[0] != caepClientC {
		t.Errorf("aud = %v, want [%s]", v.aud, caepClientC)
	}
	if v.jti == "" {
		t.Error("jti is empty (RFC 8417 RECOMMENDS a unique jti per SET)")
	}
	// A tenant-tokens-revoked event maps to account-disabled + session-revoked.
	if _, ok := v.events[caep.EventURICAEPSessionRevoked]; !ok {
		t.Errorf("events missing %q: %v", caep.EventURICAEPSessionRevoked, v.events)
	}
	if _, ok := v.events[caep.EventURIRISCAccountDisabled]; !ok {
		t.Errorf("events missing %q: %v", caep.EventURIRISCAccountDisabled, v.events)
	}
}
