package caep_test

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

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/caep"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/defaultimpl"
)

// testHTTPClient returns an http.Client that trusts exactly the supplied
// httptest TLS servers' certificates (NOT a blanket skip-verify) — proper
// trust pinning, so the transmitter still performs real TLS verification.
// Receiver endpoints MUST be https (the anti-exfil rule), so tests run TLS
// receivers.
func testHTTPClient(servers ...*httptest.Server) *http.Client {
	pool := x509.NewCertPool()
	for _, s := range servers {
		pool.AddCert(s.Certificate())
	}
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}
}

// newTLSReceiver starts an https SET receiver (production requires https).
func newTLSReceiver(r *setReceiver) *httptest.Server {
	return httptest.NewTLSServer(r.handler())
}

// receivedSET captures one delivered Security Event Token + the request
// that carried it, so assertions can inspect headers + payload.
type receivedSET struct {
	authHeader  string
	contentType string
	token       string
}

// setReceiver is an httptest receiver that records every SET it accepts.
type setReceiver struct {
	mu   sync.Mutex
	sets []receivedSET
}

func (r *setReceiver) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.sets = append(r.sets, receivedSET{
			authHeader:  req.Header.Get("Authorization"),
			contentType: req.Header.Get("Content-Type"),
			token:       string(body),
		})
		r.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}
}

func (r *setReceiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sets)
}

func (r *setReceiver) snapshot() []receivedSET {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]receivedSET(nil), r.sets...)
}

// verifiedSET is a decoded + signature-verified SET, ready for claim
// assertions.
type verifiedSET struct {
	typ    string
	iss    string
	jti    string
	aud    []string
	subID  map[string]any
	events map[string]json.RawMessage
}

// verifySET checks the compact-JWS signature against pub and decodes the
// header + payload. A failed signature fails the test — proving the SET
// was minted by the trusted JWKS key (no new RP trust setup needed).
func verifySET(t *testing.T, token string, pub ed25519.PublicKey) verifiedSET {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("SET is not a 3-part compact JWS: %q", token)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("SET signature does not verify against the issuer JWKS key")
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
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var p struct {
		Iss    string                     `json:"iss"`
		Jti    string                     `json:"jti"`
		Iat    int64                      `json:"iat"`
		Exp    int64                      `json:"exp"`
		Aud    []string                   `json:"aud"`
		SubID  map[string]any             `json:"sub_id"`
		Events map[string]json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(pb, &p); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	return verifiedSET{typ: hdr.Typ, iss: p.Iss, jti: p.Jti, aud: p.Aud, subID: p.SubID, events: p.Events}
}

// newIssuerStore builds a real Ed25519 issuer + an empty memory client
// store for a test.
func newIssuerStore() (*defaultimpl.Ed25519JWTIssuer, *defaultimpl.MemoryClientStore) {
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://idp.test"))
	return iss, defaultimpl.NewMemoryClientStore()
}

// recordTenantTokensRevoked emits the same shape the SDK's
// auditTenantTokensRevoked produces: ActorID = tenant id.
func tenantTokensRevoked(tenantID string) *audit.Event {
	return &audit.Event{Type: audit.EventTenantTokensRevoked, Outcome: audit.OutcomeSuccess, ActorID: tenantID}
}

// TestCAEPTenantEventDeliversSignedSET drives a mapped tenant event and
// asserts the affected tenant's client receives a POST carrying a valid,
// signature-verified SET with the right typ/iss/aud/events.
func TestCAEPTenantEventDeliversSignedSET(t *testing.T) {
	t.Parallel()
	recv := &setReceiver{}
	srv := newTLSReceiver(recv)
	defer srv.Close()

	iss, store := newIssuerStore()
	ctx := context.Background()
	// Client C in tenant T with a registered receiver.
	if err := store.Add(ctx, &core.Client{
		ID:       "client-c",
		TenantID: "tenant-T",
		Active:   true,
		Attributes: map[string]string{
			caep.AttrReceiverEndpoint: srv.URL,
			caep.AttrReceiverAuth:     "Bearer rp-c-secret",
		},
	}); err != nil {
		t.Fatalf("add client: %v", err)
	}

	tx := caep.NewTransmitter(iss, store,
		caep.WithIssuer("https://idp.test"),
		caep.WithHTTPClient(testHTTPClient(srv)))

	// Two emissions to assert jti uniqueness.
	_ = tx.Record(ctx, tenantTokensRevoked("tenant-T"))
	_ = tx.Record(ctx, tenantTokensRevoked("tenant-T"))

	waitFor(t, func() bool { return recv.count() == 2 }, "two SETs delivered")
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}

	sets := recv.snapshot()
	if len(sets) != 2 {
		t.Fatalf("want 2 SETs, got %d", len(sets))
	}
	var jtis []string
	for _, s := range sets {
		if s.contentType != "application/secevent+jwt" {
			t.Errorf("content-type = %q, want application/secevent+jwt", s.contentType)
		}
		if s.authHeader != "Bearer rp-c-secret" {
			t.Errorf("authorization = %q, want the client's registered auth", s.authHeader)
		}
		v := verifySET(t, s.token, iss.PublicKey())
		if v.typ != caep.SecurityEventTokenTyp {
			t.Errorf("typ = %q, want %q", v.typ, caep.SecurityEventTokenTyp)
		}
		if v.iss != "https://idp.test" {
			t.Errorf("iss = %q, want https://idp.test", v.iss)
		}
		if len(v.aud) != 1 || v.aud[0] != "client-c" {
			t.Errorf("aud = %v, want [client-c]", v.aud)
		}
		if v.jti == "" {
			t.Error("jti is empty")
		}
		if _, ok := v.events[caep.EventURICAEPSessionRevoked]; !ok {
			t.Errorf("events missing %q: %v", caep.EventURICAEPSessionRevoked, v.events)
		}
		if _, ok := v.events[caep.EventURIRISCAccountDisabled]; !ok {
			t.Errorf("events missing %q: %v", caep.EventURIRISCAccountDisabled, v.events)
		}
		jtis = append(jtis, v.jti)
	}
	if jtis[0] == jtis[1] {
		t.Errorf("jti not unique across emissions: %q", jtis[0])
	}
}

// TestCAEPNoCrossTenantLeak is the security crux: a tenant-T event must
// NOT reach a DIFFERENT tenant's client receiver.
func TestCAEPNoCrossTenantLeak(t *testing.T) {
	t.Parallel()
	recvC := &setReceiver{}
	srvC := newTLSReceiver(recvC)
	defer srvC.Close()
	recvD := &setReceiver{}
	srvD := newTLSReceiver(recvD)
	defer srvD.Close()

	iss, store := newIssuerStore()
	ctx := context.Background()
	// C in tenant-T (the affected tenant).
	if err := store.Add(ctx, &core.Client{
		ID: "client-c", TenantID: "tenant-T", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: srvC.URL},
	}); err != nil {
		t.Fatalf("add C: %v", err)
	}
	// D in tenant-OTHER (must NOT be notified for a tenant-T event).
	if err := store.Add(ctx, &core.Client{
		ID: "client-d", TenantID: "tenant-OTHER", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: srvD.URL},
	}); err != nil {
		t.Fatalf("add D: %v", err)
	}

	tx := caep.NewTransmitter(iss, store, caep.WithHTTPClient(testHTTPClient(srvC, srvD)))
	_ = tx.Record(ctx, tenantTokensRevoked("tenant-T"))

	waitFor(t, func() bool { return recvC.count() == 1 }, "C receives the SET")
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := recvD.count(); got != 0 {
		t.Fatalf("cross-tenant leak: client-d in tenant-OTHER received %d SET(s) for a tenant-T event", got)
	}
	if got := recvC.count(); got != 1 {
		t.Fatalf("client-c want 1 SET, got %d", got)
	}
}

// TestCAEPClientScopedEvent maps a refresh-token-reuse event (scopeClient
// via Event.ClientID) and asserts only that one client's receiver fires.
func TestCAEPClientScopedEvent(t *testing.T) {
	t.Parallel()
	recv := &setReceiver{}
	srv := newTLSReceiver(recv)
	defer srv.Close()
	recvOther := &setReceiver{}
	srvOther := newTLSReceiver(recvOther)
	defer srvOther.Close()

	iss, store := newIssuerStore()
	ctx := context.Background()
	if err := store.Add(ctx, &core.Client{
		ID: "owner", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: srv.URL},
	}); err != nil {
		t.Fatalf("add owner: %v", err)
	}
	if err := store.Add(ctx, &core.Client{
		ID: "bystander", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: srvOther.URL},
	}); err != nil {
		t.Fatalf("add bystander: %v", err)
	}

	tx := caep.NewTransmitter(iss, store, caep.WithHTTPClient(testHTTPClient(srv, srvOther)))
	_ = tx.Record(ctx, &audit.Event{
		Type:     audit.EventRefreshTokenReuse,
		Outcome:  audit.OutcomeFailure,
		ClientID: "owner",
		ActorID:  "user-7",
	})

	waitFor(t, func() bool { return recv.count() == 1 }, "owner receives SET")
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := recvOther.count(); got != 0 {
		t.Fatalf("bystander client received %d SET(s) for another client's event", got)
	}
	v := verifySET(t, recv.snapshot()[0].token, iss.PublicKey())
	if _, ok := v.events[caep.EventURICAEPSessionRevoked]; !ok {
		t.Errorf("events missing session-revoked: %v", v.events)
	}
	if id, _ := v.subID["id"].(string); id != "user-7" {
		t.Errorf("sub_id.id = %q, want user-7", id)
	}
}

// TestCAEPNonBlocking proves a receiver that blocks for 30s does not block
// the triggering Record call: it must return well under that.
func TestCAEPNonBlocking(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	defer close(release)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release // block until the test ends
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	iss, store := newIssuerStore()
	ctx := context.Background()
	if err := store.Add(ctx, &core.Client{
		ID: "slow", TenantID: "tenant-T", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: srv.URL},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	tx := caep.NewTransmitter(iss, store, caep.WithHTTPClient(testHTTPClient(srv)))

	done := make(chan struct{})
	go func() {
		_ = tx.Record(ctx, tenantTokensRevoked("tenant-T"))
		close(done)
	}()
	select {
	case <-done:
		// Record returned promptly despite the receiver blocking — correct.
	case <-time.After(2 * time.Second):
		t.Fatal("Record blocked on a slow receiver (must dispatch async)")
	}
}

// TestCAEPUnmappedEventSilent confirms an event the mapper doesn't know
// triggers no delivery (no broadcast-to-all for unknown events).
func TestCAEPUnmappedEventSilent(t *testing.T) {
	t.Parallel()
	recv := &setReceiver{}
	srv := newTLSReceiver(recv)
	defer srv.Close()

	iss, store := newIssuerStore()
	ctx := context.Background()
	if err := store.Add(ctx, &core.Client{
		ID: "client-c", TenantID: "tenant-T", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: srv.URL},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	tx := caep.NewTransmitter(iss, store, caep.WithHTTPClient(testHTTPClient(srv)))
	// A plain login event is not in the mapped subset.
	_ = tx.Record(ctx, &audit.Event{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, ActorID: "tenant-T"})
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := recv.count(); got != 0 {
		t.Fatalf("unmapped event broadcast %d SET(s)", got)
	}
}

// TestCAEPReceiverEndpointValidation locks the anti-exfil rule: only
// absolute https URLs are accepted.
func TestCAEPReceiverEndpointValidation(t *testing.T) {
	t.Parallel()
	good := []string{"https://rp.example.com/ssf", "https://host:8443/x"}
	bad := []string{"", "http://rp.example.com/ssf", "ftp://x/y", "rp.example.com/ssf", "://nope"}
	for _, u := range good {
		if err := caep.ValidateReceiverEndpoint(u); err != nil {
			t.Errorf("ValidateReceiverEndpoint(%q) = %v, want nil", u, err)
		}
	}
	for _, u := range bad {
		if err := caep.ValidateReceiverEndpoint(u); err == nil {
			t.Errorf("ValidateReceiverEndpoint(%q) = nil, want error", u)
		}
	}
}

// waitFor polls cond until true or a 3s deadline, failing the test on
// timeout. Used to await the async SET delivery without a fixed sleep.
func waitFor(t *testing.T, cond func() bool, what string) {
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
