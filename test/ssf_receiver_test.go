package ssotest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/caep"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/oauth"
	"github.com/snaplink/sso/security"
)

// Full-server companion to caep/receiver_test.go: it proves the HTTP wiring
// of the opt-in CAEP/SSF push-delivery RECEIVER end-to-end through a real
// *sso.Server — that POSTing a signed SET to /ssf/receive validates it,
// revokes the mapped subject's local access through the server's real
// stores, and returns the RFC 8935 ack/error statuses; and that the route
// is NOT mounted (404) when no receiver is wired (default-off proof).

const (
	ssfUpstreamIss = "https://ssf-upstream.test"
	ssfAudience    = "https://ssf-this-server.test"
	ssfLocalUser   = "ssf-local-9"
)

// ssfHarness wires a real *sso.Server with WithCAEPReceiver + the upstream
// transmitter's JWKS as the trust bundle, plus the local stores the
// revocation drives. The upstream issuer signs the inbound SET.
type ssfHarness struct {
	httpSrv  *httptest.Server
	upstream *defaultimpl.Ed25519JWTIssuer
	sessions *defaultimpl.MemorySessionManager
	refresh  *defaultimpl.MemoryRefreshTokenStore
	sink     *audit.MemorySink
}

func newSSFHarness(t *testing.T) *ssfHarness {
	t.Helper()
	ctx := context.Background()

	// The UPSTREAM transmitter's signing issuer — its published JWKS is the
	// receiver's trust bundle, so only a SET signed by this key verifies.
	upstream := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(ssfUpstreamIss))

	// THIS server's own token issuer (unrelated to the upstream key).
	local := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(ssfAudience))

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&core.Client{ID: "ssf-app", Active: true, TokenStrategy: "jwt"})
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &core.User{ID: ssfLocalUser})
	sessions := defaultimpl.NewMemorySessionManager(time.Hour)
	if _, err := sessions.Create(ctx, ssfLocalUser); err != nil {
		t.Fatalf("create session: %v", err)
	}
	refresh := defaultimpl.NewMemoryRefreshTokenStore()
	if err := refresh.Issue(ctx, "ssf-rt", &oauth.RefreshToken{
		UserID: ssfLocalUser, ClientID: "ssf-app", FamilyID: "ssf-fam",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("issue refresh: %v", err)
	}

	sink := audit.NewMemorySink(16)
	recorder := audit.New(sink)

	revoker, err := caep.NewStoreRevoker(sessions, refresh, clients)
	if err != nil {
		t.Fatalf("new revoker: %v", err)
	}
	jwks, err := upstream.JWKS(ctx)
	if err != nil {
		t.Fatalf("upstream JWKS: %v", err)
	}
	rcv, err := caep.NewReceiver(ssfAudience, defaultimpl.NewMemoryJTIReplayStore(), revoker, users,
		[]caep.TrustedTransmitter{{
			Issuer:      ssfUpstreamIss,
			JWKS:        security.NewStaticJWKS(jwks),
			SubjectMode: caep.SubjectMapOpaque,
		}},
		caep.WithReceiverAuditRecorder(recorder))
	if err != nil {
		t.Fatalf("new receiver: %v", err)
	}

	srv := sso.NewServer(
		sso.WithIssuer(ssfAudience),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(sessions),
		sso.WithRefreshTokenStore(refresh, time.Hour),
		sso.WithTokenIssuer("jwt", local),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuditRecorder(recorder),
		sso.WithCAEPReceiver(rcv),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	return &ssfHarness{httpSrv: httpSrv, upstream: upstream, sessions: sessions, refresh: refresh, sink: sink}
}

func (h *ssfHarness) signSET(t *testing.T, claims map[string]any) string {
	t.Helper()
	tok, err := h.upstream.SignJWT(context.Background(), caep.SecurityEventTokenTyp, claims)
	if err != nil {
		t.Fatalf("sign SET: %v", err)
	}
	return tok
}

func (h *ssfHarness) postSET(t *testing.T, set string) *http.Response {
	t.Helper()
	resp, err := http.Post(h.httpSrv.URL+sso.PathSSFReceive, "application/secevent+jwt", strings.NewReader(set))
	if err != nil {
		t.Fatalf("post SET: %v", err)
	}
	return resp
}

func (h *ssfHarness) localUserHasAccess(t *testing.T) bool {
	t.Helper()
	ctx := context.Background()
	sess, err := h.sessions.ListByUser(ctx, ssfLocalUser)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sess) > 0 {
		return true
	}
	if _, err := h.refresh.Inspect(ctx, "ssf-rt"); err == nil {
		return true
	}
	return false
}

func ssfSessionRevokedSET(subject, jti string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": ssfUpstreamIss,
		"jti": jti,
		"iat": now.Unix(),
		"exp": now.Add(2 * time.Minute).Unix(),
		"aud": []string{ssfAudience},
		"sub_id": map[string]any{
			"format": "opaque",
			"id":     subject,
		},
		"events": map[string]any{
			caep.EventURICAEPSessionRevoked: map[string]any{},
		},
	}
}

// TestSSFReceiver_ValidSET_RevokesAndAcks: a valid SET → 202 + the subject's
// local sessions + refresh tokens are revoked + an audit event is emitted.
func TestSSFReceiver_ValidSET_RevokesAndAcks(t *testing.T) {
	h := newSSFHarness(t)
	if !h.localUserHasAccess(t) {
		t.Fatal("precondition: local user should start with access")
	}
	resp := h.postSET(t, h.signSET(t, ssfSessionRevokedSET(ssfLocalUser, "ssf-jti-1")))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 202; body=%s", resp.StatusCode, body)
	}
	// Credential-bearing endpoint ⇒ no-store.
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if h.localUserHasAccess(t) {
		t.Fatal("local user STILL has access after a valid session-revoked SET")
	}
	// ssf_revocation audit event emitted.
	evs, _ := h.sink.Query(context.Background(), audit.Query{})
	found := false
	for _, e := range evs {
		if e.Type == caep.EventSSFRevocation {
			found = true
			if e.Metadata["ssf_issuer"] != ssfUpstreamIss {
				t.Errorf("audit ssf_issuer = %q, want %q", e.Metadata["ssf_issuer"], ssfUpstreamIss)
			}
		}
	}
	if !found {
		t.Error("no ssf_revocation audit event emitted")
	}
}

// TestSSFReceiver_ForgedSET_RejectedNoRevocation: a tampered signature →
// 400 invalid_key, the subject's access survives.
func TestSSFReceiver_ForgedSET_RejectedNoRevocation(t *testing.T) {
	h := newSSFHarness(t)
	good := h.signSET(t, ssfSessionRevokedSET(ssfLocalUser, "ssf-jti-forge"))
	forged := good[:len(good)-4] + "AAAA"

	resp := h.postSET(t, forged)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	var body struct {
		Err string `json:"err"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body.Err != caep.ErrReceiverInvalidKey {
		t.Errorf("err = %q, want %q", body.Err, caep.ErrReceiverInvalidKey)
	}
	if !h.localUserHasAccess(t) {
		t.Fatal("forged SET revoked the subject")
	}
}

// TestSSFReceiver_WrongAudience_Rejected: a SET addressed to another
// receiver → 400, no revocation (no cross-receiver replay).
func TestSSFReceiver_WrongAudience_Rejected(t *testing.T) {
	h := newSSFHarness(t)
	claims := ssfSessionRevokedSET(ssfLocalUser, "ssf-jti-aud")
	claims["aud"] = []string{"https://elsewhere.test"}
	resp := h.postSET(t, h.signSET(t, claims))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if !h.localUserHasAccess(t) {
		t.Fatal("cross-receiver SET revoked the subject")
	}
}

// TestSSFReceiver_Replay_SecondNoop: the same SET twice → first 202, second
// 400 (replayed jti), no double revocation.
func TestSSFReceiver_Replay_SecondNoop(t *testing.T) {
	h := newSSFHarness(t)
	set := h.signSET(t, ssfSessionRevokedSET(ssfLocalUser, "ssf-jti-replay"))

	resp1 := h.postSET(t, set)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusAccepted {
		t.Fatalf("first status = %d, want 202", resp1.StatusCode)
	}
	// Re-add a session so a wrongful second revocation would be visible.
	if _, err := h.sessions.Create(context.Background(), ssfLocalUser); err != nil {
		t.Fatalf("recreate session: %v", err)
	}
	resp2 := h.postSET(t, set)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed SET status = %d, want 400 (replay blocked)", resp2.StatusCode)
	}
	if sess, _ := h.sessions.ListByUser(context.Background(), ssfLocalUser); len(sess) != 1 {
		t.Errorf("replay re-revoked: sessions = %d, want the 1 survivor", len(sess))
	}
}

// TestSSFReceiver_UnmappedSubject_AckedNoRevocation: a valid SET for a
// subject with no local user → 202 but NO revocation (no wrongful DoS).
func TestSSFReceiver_UnmappedSubject_AckedNoRevocation(t *testing.T) {
	h := newSSFHarness(t)
	resp := h.postSET(t, h.signSET(t, ssfSessionRevokedSET("nobody-here", "ssf-jti-ghost")))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (valid SET for unknown subject is acked)", resp.StatusCode)
	}
	if !h.localUserHasAccess(t) {
		t.Fatal("an unmapped-subject SET revoked the real local user")
	}
}

// TestSSFReceiver_UnknownEvent_Acked: a valid SET with only an unknown event
// URI → 202, no revocation.
func TestSSFReceiver_UnknownEvent_Acked(t *testing.T) {
	h := newSSFHarness(t)
	claims := ssfSessionRevokedSET(ssfLocalUser, "ssf-jti-unknown")
	claims["events"] = map[string]any{
		"https://schemas.openid.net/secevent/risc/event-type/credential-compromise": map[string]any{},
	}
	resp := h.postSET(t, h.signSET(t, claims))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}
	if !h.localUserHasAccess(t) {
		t.Fatal("an unknown-event SET revoked the subject")
	}
}

// TestSSFReceiver_NoFreshnessClaim_Rejected: a SET omitting BOTH iat and exp
// bypasses freshness and (lacking exp) would replay indefinitely past the
// default jti window → 400 invalid_key, no revocation. Locks the FIX-2
// temporal gate at the HTTP boundary.
func TestSSFReceiver_NoFreshnessClaim_Rejected(t *testing.T) {
	h := newSSFHarness(t)
	claims := ssfSessionRevokedSET(ssfLocalUser, "ssf-jti-nofresh")
	delete(claims, "iat")
	delete(claims, "exp")
	resp := h.postSET(t, h.signSET(t, claims))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (no-freshness SET rejected)", resp.StatusCode)
	}
	var body struct {
		Err string `json:"err"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body.Err != caep.ErrReceiverInvalidKey {
		t.Errorf("err = %q, want %q", body.Err, caep.ErrReceiverInvalidKey)
	}
	if !h.localUserHasAccess(t) {
		t.Fatal("a no-freshness SET revoked the subject")
	}
}

// TestSSFReceiver_NotMounted_WhenUnwired: the DEFAULT-OFF proof — without
// WithCAEPReceiver the /ssf/receive route is NOT mounted (404).
func TestSSFReceiver_NotMounted_WhenUnwired(t *testing.T) {
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&core.Client{ID: "x", Active: true, TokenStrategy: "jwt"})
	srv := sso.NewServer(
		sso.WithIssuer("https://issuer.example"),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		// NO WithCAEPReceiver.
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	resp, err := http.Post(httpSrv.URL+sso.PathSSFReceive, "application/secevent+jwt", strings.NewReader("x.y.z"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (route must be unmounted when no receiver wired)", resp.StatusCode)
	}
}
