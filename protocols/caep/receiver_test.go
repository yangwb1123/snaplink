package caep_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/caep"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
)

// These tests drive caep.Receiver directly with REAL stores (no mocks):
//   - a real Ed25519 issuer signs the inbound SET (so the receiver verifies
//     a genuine compact-JWS signature via security.VerifyCompactJWS against
//     the issuer's published JWKS — the exact production trust path);
//   - real MemorySessionManager + MemoryRefreshTokenStore prove the
//     revocation ACTUALLY happens (the subject's sessions + refresh tokens
//     are gone afterward), and that an INVALID SET leaves them intact;
//   - the real MemoryJTIReplayStore proves a replayed SET is a no-op.
//
// The security crux is enumerated: a forged/unsigned/wrong-key/untrusted-iss/
// wrong-aud/expired/replayed SET must trigger NOTHING; a valid SET for an
// unmapped subject must ack but trigger NOTHING (no wrongful revocation).

const (
	rcvIssuer    = "https://upstream.test"            // the trusted transmitter's iss
	rcvAudience  = "https://this-server.test"         // THIS server's id the SET must target
	rcvLocalUser = "local-user-42"                    // the local user the SET maps to
	rcvOtherIss  = "https://attacker.test"            // an untrusted iss
	rcvOtherAud  = "https://some-other-receiver.test" // an aud addressed elsewhere
)

// rcvFixture bundles the real stores + a SET-signing issuer for one test.
type rcvFixture struct {
	issuer   *defaultimpl.Ed25519JWTIssuer // signs the inbound SET
	sessions *defaultimpl.MemorySessionManager
	refresh  *defaultimpl.MemoryRefreshTokenStore
	clients  *defaultimpl.MemoryClientStore
	users    *defaultimpl.MemoryUserProvider
	jti      security.JTIReplayStore
	sink     *audit.MemorySink
	recorder *audit.Recorder
	receiver *caep.Receiver
}

// newRcvFixture wires a receiver trusting exactly rcvIssuer (verified
// against that issuer's JWKS), bound to rcvAudience, with opaque subject
// mapping (the SET's sub_id.id IS the local user id). A local user
// rcvLocalUser exists with one session + one refresh token, so a valid
// session-revoked SET has something to revoke.
func newRcvFixture(t *testing.T, opts ...caep.ReceiverOption) *rcvFixture {
	t.Helper()
	ctx := context.Background()
	f := &rcvFixture{
		issuer:   defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(rcvIssuer)),
		sessions: defaultimpl.NewMemorySessionManager(time.Hour),
		refresh:  defaultimpl.NewMemoryRefreshTokenStore(),
		clients:  defaultimpl.NewMemoryClientStore(),
		users:    defaultimpl.NewMemoryUserProvider(),
		jti:      defaultimpl.NewMemoryJTIReplayStore(),
		sink:     audit.NewMemorySink(16),
	}
	f.recorder = audit.New(f.sink)

	// One registered client so the per-client refresh revocation enumerates
	// something.
	if err := f.clients.Add(ctx, &core.Client{ID: "app", Active: true}); err != nil {
		t.Fatalf("add client: %v", err)
	}
	// The local subject + its credentials.
	if err := f.users.CreateOrUpdate(ctx, &core.User{ID: rcvLocalUser}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := f.sessions.Create(ctx, rcvLocalUser); err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := f.refresh.Issue(ctx, "rt-1", &oauth.RefreshToken{
		UserID: rcvLocalUser, ClientID: "app", FamilyID: "fam-1",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("issue refresh: %v", err)
	}

	revoker, err := caep.NewStoreRevoker(f.sessions, f.refresh, f.clients)
	if err != nil {
		t.Fatalf("new revoker: %v", err)
	}

	// The trusted bundle = THIS issuer's published JWKS. So only a SET
	// signed by this issuer's key verifies.
	jwks, err := f.issuer.JWKS(ctx)
	if err != nil {
		t.Fatalf("issuer JWKS: %v", err)
	}
	trusted := []caep.TrustedTransmitter{{
		Issuer:      rcvIssuer,
		JWKS:        security.NewStaticJWKS(jwks),
		SubjectMode: caep.SubjectMapOpaque,
	}}

	ropts := append([]caep.ReceiverOption{caep.WithReceiverAuditRecorder(f.recorder)}, opts...)
	rcv, err := caep.NewReceiver(rcvAudience, f.jti, revoker, f.users, trusted, ropts...)
	if err != nil {
		t.Fatalf("new receiver: %v", err)
	}
	f.receiver = rcv
	return f
}

// signSET signs a SET payload with the fixture's issuer (typ secevent+jwt),
// exactly as a transmitter would. claims is the full SET claim set.
func (f *rcvFixture) signSET(t *testing.T, claims map[string]any) string {
	t.Helper()
	tok, err := f.issuer.SignJWT(context.Background(), caep.SecurityEventTokenTyp, claims)
	if err != nil {
		t.Fatalf("sign SET: %v", err)
	}
	return tok
}

// sessionRevokedSET builds a well-formed session-revoked SET for the given
// subject (opaque sub_id), addressed to rcvAudience, fresh, with a unique
// jti. Callers override fields for the negative cases.
func sessionRevokedSET(subject, jti string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": rcvIssuer,
		"jti": jti,
		"iat": now.Unix(),
		"exp": now.Add(2 * time.Minute).Unix(),
		"aud": []string{rcvAudience},
		"sub_id": map[string]any{
			"format": "opaque",
			"id":     subject,
		},
		"events": map[string]any{
			caep.EventURICAEPSessionRevoked: map[string]any{},
		},
	}
}

// subjectHasAccess reports whether the subject still has any session or
// refresh token — the assertion target for "was the subject revoked".
func (f *rcvFixture) subjectHasAccess(t *testing.T) bool {
	t.Helper()
	ctx := context.Background()
	sess, err := f.sessions.ListByUser(ctx, rcvLocalUser)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sess) > 0 {
		return true
	}
	// A surviving refresh token is still consumable.
	if _, err := f.refresh.Inspect(ctx, "rt-1"); err == nil {
		return true
	}
	return false
}

func (f *rcvFixture) auditTypes() []audit.EventType {
	evs, _ := f.sink.Query(context.Background(), audit.Query{})
	out := make([]audit.EventType, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Type)
	}
	return out
}

func hasAuditType(types []audit.EventType, want audit.EventType) bool {
	for _, t := range types {
		if t == want {
			return true
		}
	}
	return false
}

// --- The happy path: a valid SET revokes the mapped subject. ---

func TestReceiver_ValidSET_RevokesSubject(t *testing.T) {
	f := newRcvFixture(t)
	if !f.subjectHasAccess(t) {
		t.Fatal("precondition: subject should start with access")
	}
	set := f.signSET(t, sessionRevokedSET(rcvLocalUser, "jti-ok-1"))

	res, err := f.receiver.Receive(context.Background(), set)
	if err != nil {
		t.Fatalf("Receive returned error: %v", err)
	}
	if !res.Acked {
		t.Fatalf("valid SET not acked: %+v", res)
	}
	if !res.Acted {
		t.Fatal("valid session-revoked SET did not act")
	}
	if res.Revocation.SessionsDestroyed != 1 {
		t.Errorf("sessions destroyed = %d, want 1", res.Revocation.SessionsDestroyed)
	}
	if res.Revocation.RefreshTokensRevoked != 1 {
		t.Errorf("refresh tokens revoked = %d, want 1", res.Revocation.RefreshTokensRevoked)
	}
	if f.subjectHasAccess(t) {
		t.Fatal("subject STILL has access after a valid session-revoked SET")
	}
	if !hasAuditType(f.auditTypes(), caep.EventSSFRevocation) {
		t.Errorf("missing ssf_revocation audit event; got %v", f.auditTypes())
	}
}

// --- Forged / unsigned / wrong-key SET → rejected, NO revocation. ---

func TestReceiver_ForgedSignature_Rejected(t *testing.T) {
	f := newRcvFixture(t)
	good := f.signSET(t, sessionRevokedSET(rcvLocalUser, "jti-forge"))
	// Tamper the signature segment so the signature no longer verifies.
	forged := good[:len(good)-4] + "AAAA"

	res, err := f.receiver.Receive(context.Background(), forged)
	if err != nil {
		t.Fatalf("Receive error: %v", err)
	}
	if res.Acked {
		t.Fatalf("forged SET was acked: %+v", res)
	}
	if res.RejectCode != caep.ErrReceiverInvalidKey {
		t.Errorf("reject code = %q, want %q", res.RejectCode, caep.ErrReceiverInvalidKey)
	}
	if !f.subjectHasAccess(t) {
		t.Fatal("forged SET revoked the subject — wrongful revocation on bad signature")
	}
}

func TestReceiver_WrongKey_Rejected(t *testing.T) {
	f := newRcvFixture(t)
	// Sign with a DIFFERENT issuer (a different key) but stamp the trusted
	// iss in the claims — the signature must fail against the trusted bundle.
	attacker := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(rcvIssuer))
	tok, err := attacker.SignJWT(context.Background(), caep.SecurityEventTokenTyp, sessionRevokedSET(rcvLocalUser, "jti-wrongkey"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	res, err := f.receiver.Receive(context.Background(), tok)
	if err != nil {
		t.Fatalf("Receive error: %v", err)
	}
	if res.Acked {
		t.Fatal("SET signed by a foreign key was acked")
	}
	if f.subjectHasAccess(t) == false {
		t.Fatal("wrong-key SET revoked the subject")
	}
}

func TestReceiver_MalformedBody_Rejected(t *testing.T) {
	f := newRcvFixture(t)
	res, err := f.receiver.Receive(context.Background(), "not-a-jws")
	if err != nil {
		t.Fatalf("Receive error: %v", err)
	}
	if res.Acked {
		t.Fatal("malformed body was acked")
	}
	if res.RejectCode != caep.ErrReceiverInvalidRequest {
		t.Errorf("reject code = %q, want %q", res.RejectCode, caep.ErrReceiverInvalidRequest)
	}
	if !f.subjectHasAccess(t) {
		t.Fatal("malformed SET revoked the subject")
	}
}

// --- Untrusted iss → rejected. ---

func TestReceiver_UntrustedIssuer_Rejected(t *testing.T) {
	f := newRcvFixture(t)
	// A SET signed by an issuer whose iss is NOT in the allowlist. Build it
	// with its own issuer object (so the iss claim matches its signing key),
	// but that iss isn't trusted.
	foreign := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(rcvOtherIss))
	claims := sessionRevokedSET(rcvLocalUser, "jti-untrusted")
	claims["iss"] = rcvOtherIss
	tok, err := foreign.SignJWT(context.Background(), caep.SecurityEventTokenTyp, claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	res, err := f.receiver.Receive(context.Background(), tok)
	if err != nil {
		t.Fatalf("Receive error: %v", err)
	}
	if res.Acked {
		t.Fatal("untrusted-iss SET was acked")
	}
	if !f.subjectHasAccess(t) {
		t.Fatal("untrusted-iss SET revoked the subject")
	}
}

// --- Wrong aud (addressed elsewhere) → rejected. ---

func TestReceiver_WrongAudience_Rejected(t *testing.T) {
	f := newRcvFixture(t)
	claims := sessionRevokedSET(rcvLocalUser, "jti-aud")
	claims["aud"] = []string{rcvOtherAud} // addressed to a DIFFERENT receiver
	set := f.signSET(t, claims)

	res, err := f.receiver.Receive(context.Background(), set)
	if err != nil {
		t.Fatalf("Receive error: %v", err)
	}
	if res.Acked {
		t.Fatal("SET addressed to another receiver was acked + acted")
	}
	if !f.subjectHasAccess(t) {
		t.Fatal("cross-receiver SET revoked the subject (aud-binding failure)")
	}
}

// --- Replayed SET (same jti twice) → second is a no-op. ---

func TestReceiver_ReplayedSET_SecondRejected(t *testing.T) {
	f := newRcvFixture(t)
	set := f.signSET(t, sessionRevokedSET(rcvLocalUser, "jti-replay"))

	res1, err := f.receiver.Receive(context.Background(), set)
	if err != nil {
		t.Fatalf("first Receive error: %v", err)
	}
	if !res1.Acted {
		t.Fatal("first delivery did not act")
	}
	// Re-add a session so a (wrongful) second action would be observable.
	if _, err := f.sessions.Create(context.Background(), rcvLocalUser); err != nil {
		t.Fatalf("recreate session: %v", err)
	}

	res2, err := f.receiver.Receive(context.Background(), set)
	if err != nil {
		t.Fatalf("second Receive error: %v", err)
	}
	if res2.Acked {
		t.Fatal("replayed SET (same jti) was acked a second time — replay not blocked")
	}
	if res2.Acted {
		t.Fatal("replayed SET acted a second time")
	}
	// The freshly-added session must SURVIVE (the replay must not re-revoke).
	sess, _ := f.sessions.ListByUser(context.Background(), rcvLocalUser)
	if len(sess) != 1 {
		t.Errorf("replay re-acted: sessions = %d, want the 1 freshly-added survivor", len(sess))
	}
}

// --- Expired / stale SET → rejected. ---

func TestReceiver_ExpiredSET_Rejected(t *testing.T) {
	f := newRcvFixture(t)
	claims := sessionRevokedSET(rcvLocalUser, "jti-expired")
	// exp well in the past (beyond the default 60s skew).
	claims["iat"] = time.Now().Add(-10 * time.Minute).Unix()
	claims["exp"] = time.Now().Add(-5 * time.Minute).Unix()
	set := f.signSET(t, claims)

	res, err := f.receiver.Receive(context.Background(), set)
	if err != nil {
		t.Fatalf("Receive error: %v", err)
	}
	if res.Acked {
		t.Fatal("expired SET was acked + acted")
	}
	if !f.subjectHasAccess(t) {
		t.Fatal("expired SET revoked the subject")
	}
}

// --- Valid SET for an UNKNOWN/unmapped subject → ack, NO revocation. ---

func TestReceiver_UnmappedSubject_AckedNoRevocation(t *testing.T) {
	f := newRcvFixture(t)
	// A subject that maps to no local user (opaque id with no matching user).
	set := f.signSET(t, sessionRevokedSET("ghost-subject-does-not-exist", "jti-ghost"))

	res, err := f.receiver.Receive(context.Background(), set)
	if err != nil {
		t.Fatalf("Receive error: %v", err)
	}
	if !res.Acked {
		t.Fatalf("valid SET for an unknown subject must still be acked: %+v", res)
	}
	if res.Acted {
		t.Fatal("revoked for an unmapped subject — WRONGFUL REVOCATION")
	}
	// The real local user must be untouched (no collateral revocation).
	if !f.subjectHasAccess(t) {
		t.Fatal("an unmapped-subject SET revoked the real local user")
	}
}

// --- Unknown event URI → ack, no-op. ---

func TestReceiver_UnknownEvent_AckedNoop(t *testing.T) {
	f := newRcvFixture(t)
	claims := sessionRevokedSET(rcvLocalUser, "jti-unknown-event")
	claims["events"] = map[string]any{
		"https://schemas.openid.net/secevent/risc/event-type/credential-compromise": map[string]any{},
	}
	set := f.signSET(t, claims)

	res, err := f.receiver.Receive(context.Background(), set)
	if err != nil {
		t.Fatalf("Receive error: %v", err)
	}
	if !res.Acked {
		t.Fatalf("valid SET with an unknown event must be acked: %+v", res)
	}
	if res.Acted {
		t.Fatal("acted on an unknown event URI")
	}
	if !f.subjectHasAccess(t) {
		t.Fatal("an unknown-event SET revoked the subject")
	}
}

// --- typ gate: a token whose typ is NOT secevent+jwt is rejected even when
// validly signed by the trusted key (a plain id/access token can't be
// replayed as a SET). ---

func TestReceiver_WrongTyp_Rejected(t *testing.T) {
	f := newRcvFixture(t)
	// Sign the exact SET claims but with typ "at+jwt" (an access token typ).
	tok, err := f.issuer.SignJWT(context.Background(), "at+jwt", sessionRevokedSET(rcvLocalUser, "jti-typ"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	res, err := f.receiver.Receive(context.Background(), tok)
	if err != nil {
		t.Fatalf("Receive error: %v", err)
	}
	if res.Acked {
		t.Fatal("a non-secevent+jwt typ token was acked as a SET")
	}
	if !f.subjectHasAccess(t) {
		t.Fatal("wrong-typ token revoked the subject")
	}
}

// --- iss_sub subject mapping resolves the federation link precisely. ---

func TestReceiver_IssSubMapping_ResolvesFederationLink(t *testing.T) {
	ctx := context.Background()
	// Build a receiver in iss_sub mode: the SET's {iss,sub} resolves via
	// GetByExternalID(provider=rcvIssuer, externalID=upstream-sub).
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(rcvIssuer))
	sessions := defaultimpl.NewMemorySessionManager(time.Hour)
	refresh := defaultimpl.NewMemoryRefreshTokenStore()
	clients := defaultimpl.NewMemoryClientStore()
	users := defaultimpl.NewMemoryUserProvider()
	_ = clients.Add(ctx, &core.Client{ID: "app", Active: true})

	// A local user federated from the upstream: Provider=rcvIssuer,
	// ExternalID="upstream-sub-7" → local id "fed-local-7".
	if err := users.CreateOrUpdate(ctx, &core.User{ID: "fed-local-7", Provider: rcvIssuer, ExternalID: "upstream-sub-7"}); err != nil {
		t.Fatalf("create federated user: %v", err)
	}
	if _, err := sessions.Create(ctx, "fed-local-7"); err != nil {
		t.Fatalf("create session: %v", err)
	}

	revoker, _ := caep.NewStoreRevoker(sessions, refresh, clients)
	jwks, _ := issuer.JWKS(ctx)
	rcv, err := caep.NewReceiver(rcvAudience, defaultimpl.NewMemoryJTIReplayStore(), revoker, users,
		[]caep.TrustedTransmitter{{
			Issuer:      rcvIssuer,
			JWKS:        security.NewStaticJWKS(jwks),
			SubjectMode: caep.SubjectMapIssSub,
			// Provider is operator-pinned (REQUIRED in iss_sub mode) to the
			// transmitter's trusted federated namespace — here the upstream
			// issuer, matching the federated user's User.Provider.
			Provider: rcvIssuer,
		}})
	if err != nil {
		t.Fatalf("new receiver: %v", err)
	}

	now := time.Now()
	claims := map[string]any{
		"iss": rcvIssuer, "jti": "jti-isssub", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"aud": []string{rcvAudience},
		"sub_id": map[string]any{
			"format": "iss_sub",
			"iss":    rcvIssuer,
			"sub":    "upstream-sub-7",
		},
		"events": map[string]any{caep.EventURIRISCAccountDisabled: map[string]any{}},
	}
	tok, err := issuer.SignJWT(ctx, caep.SecurityEventTokenTyp, claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	res, err := rcv.Receive(ctx, tok)
	if err != nil {
		t.Fatalf("Receive error: %v", err)
	}
	if !res.Acted || res.LocalSubject != "fed-local-7" {
		t.Fatalf("iss_sub mapping did not resolve to fed-local-7: %+v", res)
	}
	if sess, _ := sessions.ListByUser(ctx, "fed-local-7"); len(sess) != 0 {
		t.Errorf("federated subject's session survived: %d", len(sess))
	}
}

// issSubRcvFixture bundles an iss_sub-mode receiver with a federated local
// user, for the cross-IdP-hijack tests below. The transmitter's
// operator-pinned provider is rcvIssuer; the federated user
// (fed-local-9 / Provider=rcvIssuer / ExternalID=upstream-sub-9) has one
// live session so a (wrongful or legit) revocation is observable.
type issSubRcvFixture struct {
	issuer   *defaultimpl.Ed25519JWTIssuer
	sessions *defaultimpl.MemorySessionManager
	users    *defaultimpl.MemoryUserProvider
	receiver *caep.Receiver
}

func newIssSubRcvFixture(t *testing.T) *issSubRcvFixture {
	t.Helper()
	ctx := context.Background()
	f := &issSubRcvFixture{
		issuer:   defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(rcvIssuer)),
		sessions: defaultimpl.NewMemorySessionManager(time.Hour),
		users:    defaultimpl.NewMemoryUserProvider(),
	}
	clients := defaultimpl.NewMemoryClientStore()
	_ = clients.Add(ctx, &core.Client{ID: "app", Active: true})
	if err := f.users.CreateOrUpdate(ctx, &core.User{ID: "fed-local-9", Provider: rcvIssuer, ExternalID: "upstream-sub-9"}); err != nil {
		t.Fatalf("create federated user: %v", err)
	}
	if _, err := f.sessions.Create(ctx, "fed-local-9"); err != nil {
		t.Fatalf("create session: %v", err)
	}
	revoker, _ := caep.NewStoreRevoker(f.sessions, defaultimpl.NewMemoryRefreshTokenStore(), clients)
	jwks, _ := f.issuer.JWKS(ctx)
	rcv, err := caep.NewReceiver(rcvAudience, defaultimpl.NewMemoryJTIReplayStore(), revoker, f.users,
		[]caep.TrustedTransmitter{{
			Issuer:      rcvIssuer,
			JWKS:        security.NewStaticJWKS(jwks),
			SubjectMode: caep.SubjectMapIssSub,
			Provider:    rcvIssuer, // operator-pinned trusted namespace
		}})
	if err != nil {
		t.Fatalf("new receiver: %v", err)
	}
	f.receiver = rcv
	return f
}

func (f *issSubRcvFixture) signIssSub(t *testing.T, subIDIss, sub, jti string) string {
	t.Helper()
	now := time.Now()
	subID := map[string]any{"format": "iss_sub", "sub": sub}
	if subIDIss != "" {
		subID["iss"] = subIDIss
	}
	claims := map[string]any{
		"iss": rcvIssuer, "jti": jti, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"aud":    []string{rcvAudience},
		"sub_id": subID,
		"events": map[string]any{caep.EventURIRISCAccountDisabled: map[string]any{}},
	}
	tok, err := f.issuer.SignJWT(context.Background(), caep.SecurityEventTokenTyp, claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

func (f *issSubRcvFixture) fedHasSession(t *testing.T) bool {
	t.Helper()
	sess, err := f.sessions.ListByUser(context.Background(), "fed-local-9")
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	return len(sess) > 0
}

// --- FIX 1 (HIGH): cross-IdP subject hijack is closed. ---
//
// A trusted transmitter (iss_sub, provider=rcvIssuer) mints a fully-valid SET
// whose sub_id.iss names a DIFFERENT provider. Pre-fix, the resolver fell back
// to sub_id.iss when the operator provider was empty, so the lookup happened
// under the attacker-named provider — letting transmitter A revoke users
// federated from ANY other upstream. Now the provider is operator-pinned and a
// foreign sub_id.iss is a no-op: the SET is acked (it is otherwise valid) but
// triggers NO revocation.
func TestReceiver_IssSub_ForeignSubIDIss_NoRevocation(t *testing.T) {
	f := newIssSubRcvFixture(t)
	if !f.fedHasSession(t) {
		t.Fatal("precondition: federated subject should start with a session")
	}
	// sub_id.iss names some OTHER provider; sub is the victim's external id.
	set := f.signIssSub(t, "https://some-other-provider.example", "upstream-sub-9", "jti-hijack")

	res, err := f.receiver.Receive(context.Background(), set)
	if err != nil {
		t.Fatalf("Receive error: %v", err)
	}
	if res.Acted {
		t.Fatal("a foreign sub_id.iss drove a revocation — cross-IdP subject hijack NOT closed")
	}
	if res.LocalSubject != "" {
		t.Errorf("foreign sub_id.iss mapped to a local subject %q (should be unmapped)", res.LocalSubject)
	}
	if !f.fedHasSession(t) {
		t.Fatal("the victim's session was revoked via a foreign sub_id.iss — wrongful revocation")
	}
}

// The legit path still works: a SET whose sub_id.iss == the configured
// provider, naming a real federated subject, revokes correctly.
func TestReceiver_IssSub_MatchingSubIDIss_Revokes(t *testing.T) {
	f := newIssSubRcvFixture(t)
	set := f.signIssSub(t, rcvIssuer, "upstream-sub-9", "jti-match")

	res, err := f.receiver.Receive(context.Background(), set)
	if err != nil {
		t.Fatalf("Receive error: %v", err)
	}
	if !res.Acted || res.LocalSubject != "fed-local-9" {
		t.Fatalf("matching-iss iss_sub SET did not revoke fed-local-9: %+v", res)
	}
	if f.fedHasSession(t) {
		t.Fatal("federated subject still has a session after a valid revocation")
	}
}

// The legit path also works when sub_id.iss is OMITTED (the transmitter relies
// on the operator-pinned provider): the subject still resolves + revokes.
func TestReceiver_IssSub_OmittedSubIDIss_Revokes(t *testing.T) {
	f := newIssSubRcvFixture(t)
	set := f.signIssSub(t, "", "upstream-sub-9", "jti-omit")

	res, err := f.receiver.Receive(context.Background(), set)
	if err != nil {
		t.Fatalf("Receive error: %v", err)
	}
	if !res.Acted || res.LocalSubject != "fed-local-9" {
		t.Fatalf("omitted-iss iss_sub SET did not revoke fed-local-9: %+v", res)
	}
	if f.fedHasSession(t) {
		t.Fatal("federated subject still has a session after a valid revocation")
	}
}

// Construction: iss_sub mode with an empty Provider must error (the insecure
// empty-provider default is refused at the trust boundary), while a non-empty
// Provider builds fine.
func TestNewReceiver_IssSubRequiresProvider(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	sessions := defaultimpl.NewMemorySessionManager(time.Hour)
	revoker, _ := caep.NewStoreRevoker(sessions, nil, nil)
	jti := defaultimpl.NewMemoryJTIReplayStore()
	jwks := security.NewStaticJWKS([]core.JWK{{Kty: "OKP"}})

	if _, err := caep.NewReceiver(rcvAudience, jti, revoker, users,
		[]caep.TrustedTransmitter{{Issuer: rcvIssuer, JWKS: jwks, SubjectMode: caep.SubjectMapIssSub}}); err == nil {
		t.Error("iss_sub with an empty provider must error (the provider must be operator-pinned)")
	}
	if _, err := caep.NewReceiver(rcvAudience, jti, revoker, users,
		[]caep.TrustedTransmitter{{Issuer: rcvIssuer, JWKS: jwks, SubjectMode: caep.SubjectMapIssSub, Provider: rcvIssuer}}); err != nil {
		t.Errorf("iss_sub with a non-empty provider must build: %v", err)
	}
	// opaque mode needs no provider (unchanged).
	if _, err := caep.NewReceiver(rcvAudience, jti, revoker, users,
		[]caep.TrustedTransmitter{{Issuer: rcvIssuer, JWKS: jwks, SubjectMode: caep.SubjectMapOpaque}}); err != nil {
		t.Errorf("opaque mode with no provider must still build: %v", err)
	}
}

// --- FIX 2 (MEDIUM): a SET with NO freshness claim (neither iat nor exp) is
// rejected — it would otherwise skip freshness entirely and, lacking exp,
// replay indefinitely past the default jti window. ---

func TestReceiver_NoFreshnessClaim_Rejected(t *testing.T) {
	f := newRcvFixture(t)
	claims := sessionRevokedSET(rcvLocalUser, "jti-nofresh")
	delete(claims, "iat")
	delete(claims, "exp")
	set := f.signSET(t, claims)

	res, err := f.receiver.Receive(context.Background(), set)
	if err != nil {
		t.Fatalf("Receive error: %v", err)
	}
	if res.Acked {
		t.Fatal("a SET with neither iat nor exp was acked — freshness bypass")
	}
	if res.RejectCode != caep.ErrReceiverInvalidKey {
		t.Errorf("reject code = %q, want %q", res.RejectCode, caep.ErrReceiverInvalidKey)
	}
	if res.Acted {
		t.Fatal("a no-freshness SET drove a revocation")
	}
	if !f.subjectHasAccess(t) {
		t.Fatal("a no-freshness SET revoked the subject")
	}
}

// A SET carrying ONLY a fresh iat (no exp) is still accepted + acts.
func TestReceiver_OnlyIat_Fresh_Works(t *testing.T) {
	f := newRcvFixture(t)
	claims := sessionRevokedSET(rcvLocalUser, "jti-only-iat")
	delete(claims, "exp")
	claims["iat"] = time.Now().Unix()
	set := f.signSET(t, claims)

	res, err := f.receiver.Receive(context.Background(), set)
	if err != nil {
		t.Fatalf("Receive error: %v", err)
	}
	if !res.Acted {
		t.Fatalf("a fresh iat-only SET did not act: %+v", res)
	}
	if f.subjectHasAccess(t) {
		t.Fatal("subject still has access after a fresh iat-only revocation")
	}
}

// A SET carrying ONLY a future-valid exp (no iat) is still accepted + acts;
// an expired exp-only SET is still rejected.
func TestReceiver_OnlyExp_FreshAndExpired(t *testing.T) {
	f := newRcvFixture(t)

	fresh := sessionRevokedSET(rcvLocalUser, "jti-only-exp-fresh")
	delete(fresh, "iat")
	fresh["exp"] = time.Now().Add(2 * time.Minute).Unix()
	res, err := f.receiver.Receive(context.Background(), f.signSET(t, fresh))
	if err != nil {
		t.Fatalf("Receive (fresh exp-only) error: %v", err)
	}
	if !res.Acted {
		t.Fatalf("a fresh exp-only SET did not act: %+v", res)
	}
	if f.subjectHasAccess(t) {
		t.Fatal("subject survived a fresh exp-only revocation")
	}

	// Re-add a session, then an EXPIRED exp-only SET must be rejected.
	if _, err := f.sessions.Create(context.Background(), rcvLocalUser); err != nil {
		t.Fatalf("recreate session: %v", err)
	}
	expired := sessionRevokedSET(rcvLocalUser, "jti-only-exp-old")
	delete(expired, "iat")
	expired["exp"] = time.Now().Add(-5 * time.Minute).Unix()
	res2, err := f.receiver.Receive(context.Background(), f.signSET(t, expired))
	if err != nil {
		t.Fatalf("Receive (expired exp-only) error: %v", err)
	}
	if res2.Acked {
		t.Fatal("an expired exp-only SET was acked")
	}
	if !f.subjectHasAccess(t) {
		t.Fatal("an expired exp-only SET revoked the subject")
	}
}

// --- Constructor guards: a misconfigured receiver must error, not build. ---

func TestNewReceiver_RequiresAudienceAndTransmitters(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	sessions := defaultimpl.NewMemorySessionManager(time.Hour)
	revoker, _ := caep.NewStoreRevoker(sessions, nil, nil)
	jti := defaultimpl.NewMemoryJTIReplayStore()
	good := []caep.TrustedTransmitter{{Issuer: rcvIssuer, JWKS: security.NewStaticJWKS([]core.JWK{{Kty: "OKP"}})}}

	if _, err := caep.NewReceiver("", jti, revoker, users, good); err == nil {
		t.Error("empty audience must error (aud-binding cannot be lax)")
	}
	if _, err := caep.NewReceiver(rcvAudience, nil, revoker, users, good); err == nil {
		t.Error("nil JTI replay store must error (replay defense mandatory)")
	}
	if _, err := caep.NewReceiver(rcvAudience, jti, revoker, users, nil); err == nil {
		t.Error("no trusted transmitters must error")
	}
	if _, err := caep.NewReceiver(rcvAudience, jti, revoker, users, []caep.TrustedTransmitter{{Issuer: "", JWKS: security.NewStaticJWKS([]core.JWK{{Kty: "OKP"}})}}); err == nil {
		t.Error("transmitter without issuer must error")
	}
	if _, err := caep.NewReceiver(rcvAudience, jti, revoker, users, []caep.TrustedTransmitter{{Issuer: rcvIssuer, JWKS: nil}}); err == nil {
		t.Error("transmitter without JWKS must error")
	}
}

func TestNewStoreRevoker_RequiresAtLeastOneLeg(t *testing.T) {
	if _, err := caep.NewStoreRevoker(nil, nil, nil); err == nil {
		t.Error("a revoker that can do nothing must error")
	}
}

// jsonRT confirms a SET's events claim round-trips as the receiver expects
// (defensive — the receiver reads events as json.RawMessage).
func TestReceiver_EventsClaimShape(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{caep.EventURICAEPSessionRevoked: map[string]any{}})
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("events claim does not round-trip: %v", err)
	}
	if _, ok := m[caep.EventURICAEPSessionRevoked]; !ok {
		t.Error("session-revoked URI missing from round-tripped events")
	}
}

// failOnceRevoker errors on the first RevokeAllForSubject, then delegates.
type failOnceRevoker struct {
	inner caep.SubjectRevoker
	calls int
}

func (r *failOnceRevoker) RevokeAllForSubject(ctx context.Context, localUserID string) (caep.RevocationResult, error) {
	r.calls++
	if r.calls == 1 {
		return caep.RevocationResult{}, errors.New("transient revoke-store outage")
	}
	return r.inner.RevokeAllForSubject(ctx, localUserID)
}

// TestReceiver_RetryAfterRevokeError_SecondDeliveryRevokes guards the fail-closed
// retry recovery: a transient revoke-store outage on the first delivery returns a
// RETRYABLE error (the handler answers the transmitter with 500); the retried SET
// (same jti) MUST still revoke. The consumed jti is rolled back on the error path
// so the resend is admitted rather than dropped as a replay. Without the rollback
// the subject keeps all access forever despite a valid session-revoked SET.
func TestReceiver_RetryAfterRevokeError_SecondDeliveryRevokes(t *testing.T) {
	ctx := context.Background()
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(rcvIssuer))
	sessions := defaultimpl.NewMemorySessionManager(time.Hour)
	refresh := defaultimpl.NewMemoryRefreshTokenStore()
	clients := defaultimpl.NewMemoryClientStore()
	users := defaultimpl.NewMemoryUserProvider()
	_ = clients.Add(ctx, &core.Client{ID: "app", Active: true})
	_ = users.CreateOrUpdate(ctx, &core.User{ID: rcvLocalUser})
	if _, err := sessions.Create(ctx, rcvLocalUser); err != nil {
		t.Fatalf("create session: %v", err)
	}
	storeRevoker, _ := caep.NewStoreRevoker(sessions, refresh, clients)
	revoker := &failOnceRevoker{inner: storeRevoker}
	jwks, _ := issuer.JWKS(ctx)
	rcv, err := caep.NewReceiver(rcvAudience, defaultimpl.NewMemoryJTIReplayStore(), revoker, users,
		[]caep.TrustedTransmitter{{Issuer: rcvIssuer, JWKS: security.NewStaticJWKS(jwks), SubjectMode: caep.SubjectMapOpaque}})
	if err != nil {
		t.Fatalf("new receiver: %v", err)
	}

	set, err := issuer.SignJWT(ctx, caep.SecurityEventTokenTyp, sessionRevokedSET(rcvLocalUser, "jti-retry"))
	if err != nil {
		t.Fatalf("sign SET: %v", err)
	}

	// First delivery: revoke-store errors -> retryable error; jti rolled back.
	if _, err := rcv.Receive(ctx, set); err == nil {
		t.Fatal("first delivery must return a retryable error (revoke-store outage)")
	}
	if sess, _ := sessions.ListByUser(ctx, rcvLocalUser); len(sess) != 1 {
		t.Fatalf("session should survive the failed first delivery, got %d", len(sess))
	}

	// Retry the SAME SET (same jti): must be admitted (not a replay) and revoke.
	res, err := rcv.Receive(ctx, set)
	if err != nil {
		t.Fatalf("retry Receive error: %v", err)
	}
	if !res.Acted {
		t.Fatal("retried SET was dropped as a replay instead of revoking (jti rollback failed)")
	}
	if sess, _ := sessions.ListByUser(ctx, rcvLocalUser); len(sess) != 0 {
		t.Errorf("subject session survived after a successful retry: %d", len(sess))
	}
}
