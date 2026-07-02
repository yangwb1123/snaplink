package caep_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/caep"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
)

// These tests extend receiver_test.go to cover the receiver's option
// setters, the transient-store-error fail-closed paths (resolver error,
// jti-replay store error, revoke error — none of which ack), the
// no-issuer / top-level-sub-fallback / no-jti / iss-mismatch validation
// branches, AllowedEvents narrowing, the duplicate-transmitter +
// missing-UserProvider constructor guards, custom metric/logger/resolver
// wiring, and the StoreRevoker session-only / refresh-only legs. REAL
// stores + a real Ed25519 SET signer; thin real-impl wrappers (NOT mocks)
// inject store errors.

var errResolveBoom = errors.New("caep_test: resolver store outage")

// errUserProvider wraps the real MemoryUserProvider and returns a
// NON-ErrNoSuchUser error from GetByID/GetByExternalID — the transient
// outage the resolver must fail CLOSED on (no action, no ack, retryable).
type errUserProvider struct {
	*defaultimpl.MemoryUserProvider
}

func (e *errUserProvider) GetByID(context.Context, string) (*core.User, error) {
	return nil, errResolveBoom
}

func (e *errUserProvider) GetByExternalID(context.Context, string, string) (*core.User, error) {
	return nil, errResolveBoom
}

var _ core.UserProvider = (*errUserProvider)(nil)

// errRevoker is a SubjectRevoker that always errors — drives the
// post-validation revoke-store-error path (surfaced as a non-nil error so
// the transmitter retries; NOT acked-as-done).
type errRevoker struct{}

func (errRevoker) RevokeAllForSubject(context.Context, string) (caep.RevocationResult, error) {
	return caep.RevocationResult{}, errors.New("caep_test: revoke store down")
}

var _ caep.SubjectRevoker = errRevoker{}

// NOTE: caep.SubjectResolver cannot be implemented from this external test
// package because ResolveLocalSubject takes the UNEXPORTED setSubjectID type.
// So the receiver's CUSTOM-resolver path is exercised only via the default
// userProviderResolver (the in-package, real resolver) plus the nil-resolver
// option below; a bespoke resolver is not externally constructible by design.

// --- option setters (zero-coverage closers) ---

func TestReceiverOptions_AllApplied(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(rcvIssuer))
	jwks, _ := issuer.JWKS(ctx)
	sessions := defaultimpl.NewMemorySessionManager(time.Hour)
	revoker, _ := caep.NewStoreRevoker(sessions, nil, nil)
	users := defaultimpl.NewMemoryUserProvider()

	metric := &capturingMetric{}
	logger := &capturingLogger{}

	rcv, err := caep.NewReceiver(rcvAudience, defaultimpl.NewMemoryJTIReplayStore(), revoker, users,
		[]caep.TrustedTransmitter{{Issuer: rcvIssuer, JWKS: security.NewStaticJWKS(jwks)}},
		caep.WithReceiverMaxClockSkew(2*time.Minute),
		caep.WithReceiverAuditRecorder(audit.New(audit.NewMemorySink(4))),
		caep.WithReceiverMetric(metric.record),
		caep.WithReceiverLogger(logger),
		// A nil custom resolver must be ignored (the default UserProvider one stays).
		caep.WithReceiverSubjectResolver(nil),
	)
	if err != nil {
		t.Fatalf("NewReceiver with all options: %v", err)
	}
	if rcv == nil {
		t.Fatal("NewReceiver returned nil")
	}
	// A negative skew is ignored by the setter (no panic, builds fine).
	if _, err := caep.NewReceiver(rcvAudience, defaultimpl.NewMemoryJTIReplayStore(), revoker, users,
		[]caep.TrustedTransmitter{{Issuer: rcvIssuer, JWKS: security.NewStaticJWKS(jwks)}},
		caep.WithReceiverMaxClockSkew(-1)); err != nil {
		t.Errorf("negative skew override must be ignored, got %v", err)
	}
}

// --- the rejected metric fires on a validation failure (covers reject()'s
// metric leg + WithReceiverMetric). ---

func TestReceiver_RejectedMetric(t *testing.T) {
	t.Parallel()
	metric := &capturingMetric{}
	f := newRcvFixture(t, caep.WithReceiverMetric(metric.record))
	if _, err := f.receiver.Receive(context.Background(), "not-a-jws"); err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if !metric.has(caep.ReceiverOutcomeRejected) {
		t.Errorf("rejected outcome not recorded; got %v", metric.snapshot())
	}
}

// --- the noop + revoked metric labels fire (covers WithReceiverMetric on the
// happy + valid-but-noop paths). ---

func TestReceiver_RevokedAndNoopMetrics(t *testing.T) {
	t.Parallel()
	metric := &capturingMetric{}
	f := newRcvFixture(t, caep.WithReceiverMetric(metric.record))

	// Revoked: a valid SET that maps + acts.
	set := f.signSET(t, sessionRevokedSET(rcvLocalUser, "jti-metric-rev"))
	if _, err := f.receiver.Receive(context.Background(), set); err != nil {
		t.Fatalf("Receive (revoked): %v", err)
	}
	if !metric.has(caep.ReceiverOutcomeRevoked) {
		t.Errorf("revoked outcome not recorded; got %v", metric.snapshot())
	}

	// Noop: a valid SET for an unmapped subject.
	noop := f.signSET(t, sessionRevokedSET("ghost", "jti-metric-noop"))
	if _, err := f.receiver.Receive(context.Background(), noop); err != nil {
		t.Fatalf("Receive (noop): %v", err)
	}
	if !metric.has(caep.ReceiverOutcomeNoop) {
		t.Errorf("noop outcome not recorded; got %v", metric.snapshot())
	}
}

// --- a SET with NO iss in its (unverified) payload ⇒ rejected (cannot select a
// trust bundle). The pre-parse iss-read failure path. ---

func TestReceiver_NoIssuer_Rejected(t *testing.T) {
	t.Parallel()
	f := newRcvFixture(t)
	claims := sessionRevokedSET(rcvLocalUser, "jti-noiss")
	delete(claims, "iss")
	set := f.signSET(t, claims)

	res, err := f.receiver.Receive(context.Background(), set)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if res.Acked {
		t.Fatal("a SET with no iss was acked")
	}
	if res.RejectCode != caep.ErrReceiverInvalidKey {
		t.Errorf("reject code = %q, want %q", res.RejectCode, caep.ErrReceiverInvalidKey)
	}
	if !f.subjectHasAccess(t) {
		t.Fatal("a no-iss SET revoked the subject")
	}
}

// --- a SET carrying NO jti ⇒ rejected (a stripped jti must not bypass the
// replay guard). ---

func TestReceiver_NoJTI_Rejected(t *testing.T) {
	t.Parallel()
	f := newRcvFixture(t)
	claims := sessionRevokedSET(rcvLocalUser, "ignored")
	delete(claims, "jti")
	set := f.signSET(t, claims)

	res, err := f.receiver.Receive(context.Background(), set)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if res.Acked {
		t.Fatal("a SET with no jti was acked (replay-guard bypass)")
	}
	if !f.subjectHasAccess(t) {
		t.Fatal("a no-jti SET revoked the subject")
	}
}

// --- a top-level `sub` (no sub_id object) is used as the opaque subject
// fallback (covers inboundSETClaims.subjectID()'s sub-fallback branch). ---

func TestReceiver_TopLevelSubFallback_Revokes(t *testing.T) {
	t.Parallel()
	f := newRcvFixture(t)
	now := time.Now()
	claims := map[string]any{
		"iss": rcvIssuer, "jti": "jti-toplevel-sub", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"aud":    []string{rcvAudience},
		"sub":    rcvLocalUser, // top-level sub, NO sub_id object
		"events": map[string]any{caep.EventURICAEPSessionRevoked: map[string]any{}},
	}
	set := f.signSET(t, claims)

	res, err := f.receiver.Receive(context.Background(), set)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if !res.Acted || res.LocalSubject != rcvLocalUser {
		t.Fatalf("top-level sub did not map+act: %+v", res)
	}
	if f.subjectHasAccess(t) {
		t.Fatal("subject still has access after a top-level-sub SET")
	}
}

// --- a SET with NEITHER sub_id NOR sub ⇒ unmapped (subjectID returns empty),
// acked + no-op. ---

func TestReceiver_NoSubject_AckedNoop(t *testing.T) {
	t.Parallel()
	f := newRcvFixture(t)
	now := time.Now()
	claims := map[string]any{
		"iss": rcvIssuer, "jti": "jti-nosub", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"aud":    []string{rcvAudience},
		"events": map[string]any{caep.EventURICAEPSessionRevoked: map[string]any{}},
	}
	set := f.signSET(t, claims)

	res, err := f.receiver.Receive(context.Background(), set)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if !res.Acked {
		t.Fatalf("a valid no-subject SET must be acked: %+v", res)
	}
	if res.Acted {
		t.Fatal("a no-subject SET acted (wrongful revocation)")
	}
	if !f.subjectHasAccess(t) {
		t.Fatal("a no-subject SET revoked the real subject")
	}
}

// --- a single-string aud (not an array) still binds (covers setAudClaim's
// single-string UnmarshalJSON path through the full pipeline). ---

func TestReceiver_SingleStringAud_Binds(t *testing.T) {
	t.Parallel()
	f := newRcvFixture(t)
	claims := sessionRevokedSET(rcvLocalUser, "jti-strAud")
	claims["aud"] = rcvAudience // a bare string, not []string
	set := f.signSET(t, claims)

	res, err := f.receiver.Receive(context.Background(), set)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if !res.Acted {
		t.Fatalf("a single-string aud SET did not bind+act: %+v", res)
	}
}

// --- a resolver transient error (NOT ErrNoSuchUser) ⇒ fail-closed: no ack, a
// non-nil error surfaced (the transmitter retries), no revocation. ---

func TestReceiver_ResolverStoreError_FailsClosedNoAck(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(rcvIssuer))
	sessions := defaultimpl.NewMemorySessionManager(time.Hour)
	clients := defaultimpl.NewMemoryClientStore()
	_ = clients.Add(ctx, &core.Client{ID: "app", Active: true})
	revoker, _ := caep.NewStoreRevoker(sessions, nil, nil)
	jwks, _ := issuer.JWKS(ctx)

	// The default resolver backed by a UserProvider that errors transiently.
	users := &errUserProvider{MemoryUserProvider: defaultimpl.NewMemoryUserProvider()}
	rcv, err := caep.NewReceiver(rcvAudience, defaultimpl.NewMemoryJTIReplayStore(), revoker, users,
		[]caep.TrustedTransmitter{{Issuer: rcvIssuer, JWKS: security.NewStaticJWKS(jwks)}})
	if err != nil {
		t.Fatalf("new receiver: %v", err)
	}

	now := time.Now()
	claims := map[string]any{
		"iss": rcvIssuer, "jti": "jti-resolve-err", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"aud":    []string{rcvAudience},
		"sub_id": map[string]any{"format": "opaque", "id": "whoever"},
		"events": map[string]any{caep.EventURICAEPSessionRevoked: map[string]any{}},
	}
	tok, err := issuer.SignJWT(ctx, caep.SecurityEventTokenTyp, claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	res, err := rcv.Receive(ctx, tok)
	if err == nil {
		t.Fatal("a resolver store error must surface a non-nil error (fail-closed, retryable)")
	}
	if res.Acked {
		t.Fatal("a resolver store error must NOT ack the SET")
	}
}

// --- a revoke-store error AFTER full validation ⇒ surfaced as a non-nil error
// (the validated intent is real; the transmitter retries). ---

func TestReceiver_RevokeStoreError_Surfaced(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(rcvIssuer))
	users := defaultimpl.NewMemoryUserProvider()
	if err := users.CreateOrUpdate(ctx, &core.User{ID: rcvLocalUser}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	jwks, _ := issuer.JWKS(ctx)
	sink := audit.NewMemorySink(8)
	rcv, err := caep.NewReceiver(rcvAudience, defaultimpl.NewMemoryJTIReplayStore(), errRevoker{}, users,
		[]caep.TrustedTransmitter{{Issuer: rcvIssuer, JWKS: security.NewStaticJWKS(jwks)}},
		caep.WithReceiverAuditRecorder(audit.New(sink)))
	if err != nil {
		t.Fatalf("new receiver: %v", err)
	}

	now := time.Now()
	claims := map[string]any{
		"iss": rcvIssuer, "jti": "jti-revoke-err", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"aud":    []string{rcvAudience},
		"sub_id": map[string]any{"format": "opaque", "id": rcvLocalUser},
		"events": map[string]any{caep.EventURICAEPSessionRevoked: map[string]any{}},
	}
	tok, _ := issuer.SignJWT(ctx, caep.SecurityEventTokenTyp, claims)
	res, err := rcv.Receive(ctx, tok)
	if err == nil {
		t.Fatal("a revoke store error must surface a non-nil error")
	}
	if res.Acked {
		t.Fatal("a failed revoke must not ack (the transmitter should retry)")
	}
	// A failed-attempt ssf_revocation audit must still be written.
	evs, _ := sink.Query(ctx, audit.Query{})
	var sawFail bool
	for _, e := range evs {
		if e.Type == caep.EventSSFRevocation && e.Outcome == audit.OutcomeFailure {
			sawFail = true
		}
	}
	if !sawFail {
		t.Errorf("no failed ssf_revocation audit event; got %d events", len(evs))
	}
}

// --- a jti-replay store error ⇒ fail-closed (rejected), with the logger leg
// exercised. ---

// errJTIReplay wraps the real memory JTI store and always errors MarkSeen.
type errJTIReplay struct{}

func (errJTIReplay) MarkSeen(context.Context, string, time.Time) (bool, error) {
	return false, errors.New("caep_test: jti store down")
}

var _ security.JTIReplayStore = errJTIReplay{}

func TestReceiver_JTIStoreError_FailsClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(rcvIssuer))
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &core.User{ID: rcvLocalUser})
	sessions := defaultimpl.NewMemorySessionManager(time.Hour)
	_, _ = sessions.Create(ctx, rcvLocalUser)
	revoker, _ := caep.NewStoreRevoker(sessions, nil, nil)
	jwks, _ := issuer.JWKS(ctx)
	logger := &capturingLogger{}

	rcv, err := caep.NewReceiver(rcvAudience, errJTIReplay{}, revoker, users,
		[]caep.TrustedTransmitter{{Issuer: rcvIssuer, JWKS: security.NewStaticJWKS(jwks)}},
		caep.WithReceiverLogger(logger))
	if err != nil {
		t.Fatalf("new receiver: %v", err)
	}

	now := time.Now()
	claims := map[string]any{
		"iss": rcvIssuer, "jti": "jti-store-err", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"aud":    []string{rcvAudience},
		"sub_id": map[string]any{"format": "opaque", "id": rcvLocalUser},
		"events": map[string]any{caep.EventURICAEPSessionRevoked: map[string]any{}},
	}
	tok, _ := issuer.SignJWT(ctx, caep.SecurityEventTokenTyp, claims)
	res, err := rcv.Receive(ctx, tok)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if res.Acked {
		t.Fatal("a jti-store error must reject (fail-closed), not ack")
	}
	if res.RejectCode != caep.ErrReceiverInvalidKey {
		t.Errorf("reject code = %q, want %q", res.RejectCode, caep.ErrReceiverInvalidKey)
	}
	if logger.count() == 0 {
		t.Error("a jti-store error did not log")
	}
	// The session must SURVIVE (no action on store uncertainty).
	sess, _ := sessions.ListByUser(ctx, rcvLocalUser)
	if len(sess) != 1 {
		t.Errorf("a jti-store error revoked the subject: sessions = %d, want 1", len(sess))
	}
}

// --- AllowedEvents narrowing: a transmitter restricted to session-revoked must
// IGNORE an account-disabled SET (ack + no-op) while still acting on a
// session-revoked one. ---

func TestReceiver_AllowedEvents_Narrowing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(rcvIssuer))
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &core.User{ID: rcvLocalUser})
	sessions := defaultimpl.NewMemorySessionManager(time.Hour)
	_, _ = sessions.Create(ctx, rcvLocalUser)
	revoker, _ := caep.NewStoreRevoker(sessions, nil, nil)
	jwks, _ := issuer.JWKS(ctx)

	rcv, err := caep.NewReceiver(rcvAudience, defaultimpl.NewMemoryJTIReplayStore(), revoker, users,
		[]caep.TrustedTransmitter{{
			Issuer:        rcvIssuer,
			JWKS:          security.NewStaticJWKS(jwks),
			AllowedEvents: []string{caep.EventURICAEPSessionRevoked}, // ONLY this
		}})
	if err != nil {
		t.Fatalf("new receiver: %v", err)
	}
	sign := func(jti string, eventURI string) string {
		now := time.Now()
		claims := map[string]any{
			"iss": rcvIssuer, "jti": jti, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
			"aud":    []string{rcvAudience},
			"sub_id": map[string]any{"format": "opaque", "id": rcvLocalUser},
			"events": map[string]any{eventURI: map[string]any{}},
		}
		tok, _ := issuer.SignJWT(ctx, caep.SecurityEventTokenTyp, claims)
		return tok
	}

	// account-disabled is NOT in AllowedEvents ⇒ acked but no-op.
	res, err := rcv.Receive(ctx, sign("jti-disallowed", caep.EventURIRISCAccountDisabled))
	if err != nil {
		t.Fatalf("Receive (disallowed): %v", err)
	}
	if !res.Acked || res.Acted {
		t.Fatalf("a disallowed event should ack+noop, got %+v", res)
	}
	if sess, _ := sessions.ListByUser(ctx, rcvLocalUser); len(sess) != 1 {
		t.Errorf("a disallowed event revoked the subject: sessions = %d", len(sess))
	}

	// session-revoked IS allowed ⇒ acts.
	res2, err := rcv.Receive(ctx, sign("jti-allowed", caep.EventURICAEPSessionRevoked))
	if err != nil {
		t.Fatalf("Receive (allowed): %v", err)
	}
	if !res2.Acted {
		t.Fatalf("an allowed event did not act: %+v", res2)
	}
}

// --- constructor guards not already covered: duplicate transmitter issuer +
// missing UserProvider with no custom resolver. ---

func TestNewReceiver_DuplicateIssuer_Errors(t *testing.T) {
	t.Parallel()
	users := defaultimpl.NewMemoryUserProvider()
	sessions := defaultimpl.NewMemorySessionManager(time.Hour)
	revoker, _ := caep.NewStoreRevoker(sessions, nil, nil)
	jwks := security.NewStaticJWKS([]core.JWK{{Kty: "OKP"}})

	_, err := caep.NewReceiver(rcvAudience, defaultimpl.NewMemoryJTIReplayStore(), revoker, users,
		[]caep.TrustedTransmitter{
			{Issuer: rcvIssuer, JWKS: jwks},
			{Issuer: rcvIssuer, JWKS: jwks}, // duplicate iss
		})
	if err == nil {
		t.Fatal("duplicate trusted-transmitter issuer must error")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error %q should mention the duplicate", err)
	}
}

func TestNewReceiver_NilUserProviderNoResolver_Errors(t *testing.T) {
	t.Parallel()
	sessions := defaultimpl.NewMemorySessionManager(time.Hour)
	revoker, _ := caep.NewStoreRevoker(sessions, nil, nil)
	jwks := security.NewStaticJWKS([]core.JWK{{Kty: "OKP"}})

	// nil UserProvider AND no custom resolver ⇒ error (the default resolver
	// has no backing store). A custom resolver can't be supplied from this
	// external test package (the SubjectResolver method takes an unexported
	// type), so only the error path is asserted here.
	if _, err := caep.NewReceiver(rcvAudience, defaultimpl.NewMemoryJTIReplayStore(), revoker, nil,
		[]caep.TrustedTransmitter{{Issuer: rcvIssuer, JWKS: jwks}}); err == nil {
		t.Fatal("nil UserProvider with no custom resolver must error")
	}
}

// --- StoreRevoker single-leg coverage: session-only and refresh-only. ---

func TestStoreRevoker_SessionOnly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessions := defaultimpl.NewMemorySessionManager(time.Hour)
	if _, err := sessions.Create(ctx, "u1"); err != nil {
		t.Fatalf("create session: %v", err)
	}
	rev, err := caep.NewStoreRevoker(sessions, nil, nil) // session leg only
	if err != nil {
		t.Fatalf("new revoker: %v", err)
	}
	res, err := rev.RevokeAllForSubject(ctx, "u1")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if res.SessionsDestroyed != 1 {
		t.Errorf("sessions destroyed = %d, want 1", res.SessionsDestroyed)
	}
	if res.RefreshTokensRevoked != 0 {
		t.Errorf("refresh revoked = %d, want 0 (no refresh leg)", res.RefreshTokensRevoked)
	}
	// Idempotent: a second call finds nothing.
	res2, _ := rev.RevokeAllForSubject(ctx, "u1")
	if res2.SessionsDestroyed != 0 {
		t.Errorf("second revoke destroyed %d sessions, want 0 (idempotent)", res2.SessionsDestroyed)
	}
}

func TestStoreRevoker_RefreshOnly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	refresh := defaultimpl.NewMemoryRefreshTokenStore()
	clients := defaultimpl.NewMemoryClientStore()
	_ = clients.Add(ctx, &core.Client{ID: "app", Active: true})
	if err := refresh.Issue(ctx, "rt-x", &oauth.RefreshToken{
		UserID: "u2", ClientID: "app", FamilyID: "fam-x", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	rev, err := caep.NewStoreRevoker(nil, refresh, clients) // refresh leg only
	if err != nil {
		t.Fatalf("new revoker: %v", err)
	}
	res, err := rev.RevokeAllForSubject(ctx, "u2")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if res.RefreshTokensRevoked != 1 {
		t.Errorf("refresh revoked = %d, want 1", res.RefreshTokensRevoked)
	}
	if res.SessionsDestroyed != 0 {
		t.Errorf("sessions destroyed = %d, want 0 (no session leg)", res.SessionsDestroyed)
	}
}

// TestStoreRevoker_TrustedDeviceLeg proves an upstream session-revoked /
// account-disabled SET (the receiver's ONLY reason to call
// RevokeAllForSubject) also kills any standing "remember this device"
// MFA-skip grant for the subject — otherwise a compromised account flagged
// by a federated IdP would still let the attacker skip MFA locally via an
// old trusted-device token that predates the compromise signal. The leg is
// opt-in (WithTrustedDeviceRevocation) so every pre-existing 3-arg
// NewStoreRevoker call site is unaffected.
func TestStoreRevoker_TrustedDeviceLeg(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessions := defaultimpl.NewMemorySessionManager(time.Hour)
	devices := defaultimpl.NewMemoryTrustedDeviceStore()
	if _, _, err := devices.Trust(ctx, "u4", "app", "", time.Hour); err != nil {
		t.Fatalf("seed trust: %v", err)
	}
	rev, err := caep.NewStoreRevoker(sessions, nil, nil, caep.WithTrustedDeviceRevocation(devices))
	if err != nil {
		t.Fatalf("new revoker: %v", err)
	}
	res, err := rev.RevokeAllForSubject(ctx, "u4")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if res.TrustedDevicesRevoked != 1 {
		t.Errorf("trusted devices revoked = %d, want 1", res.TrustedDevicesRevoked)
	}
	remaining, err := devices.ListByUser(ctx, "u4")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(remaining) != 0 {
		t.Errorf("remaining trusted devices = %d, want 0", len(remaining))
	}
}

// TestStoreRevoker_NoTrustedDeviceLeg_LeavesCountZero proves the leg is
// truly opt-in: without WithTrustedDeviceRevocation, RevokeAllForSubject
// never touches a wired TrustedDeviceStore it wasn't given.
func TestStoreRevoker_NoTrustedDeviceLeg_LeavesCountZero(t *testing.T) {
	t.Parallel()
	sessions := defaultimpl.NewMemorySessionManager(time.Hour)
	rev, _ := caep.NewStoreRevoker(sessions, nil, nil)
	res, err := rev.RevokeAllForSubject(context.Background(), "u5")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if res.TrustedDevicesRevoked != 0 {
		t.Errorf("trusted devices revoked = %d, want 0 (leg not wired)", res.TrustedDevicesRevoked)
	}
}

// --- StoreRevoker rejects an empty subject. ---

func TestStoreRevoker_EmptySubject_Errors(t *testing.T) {
	t.Parallel()
	sessions := defaultimpl.NewMemorySessionManager(time.Hour)
	rev, _ := caep.NewStoreRevoker(sessions, nil, nil)
	if _, err := rev.RevokeAllForSubject(context.Background(), ""); err == nil {
		t.Error("RevokeAllForSubject with an empty subject must error")
	}
}

// --- StoreRevoker: a ClientStore.List error during the refresh leg is
// collected (best-effort) and surfaced, while the session leg still runs. ---

func TestStoreRevoker_RefreshListError_Collected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessions := defaultimpl.NewMemorySessionManager(time.Hour)
	if _, err := sessions.Create(ctx, "u3"); err != nil {
		t.Fatalf("create session: %v", err)
	}
	// A ClientStore that errors List (so the per-client refresh enumeration
	// can't run). Reuse the transmitter test's errClientStore (failList).
	clients := &errClientStore{MemoryClientStore: defaultimpl.NewMemoryClientStore(), failList: true}
	rev, err := caep.NewStoreRevoker(sessions, defaultimpl.NewMemoryRefreshTokenStore(), clients)
	if err != nil {
		t.Fatalf("new revoker: %v", err)
	}
	res, err := rev.RevokeAllForSubject(ctx, "u3")
	if err == nil {
		t.Fatal("a ClientStore.List error must be collected + surfaced")
	}
	// The session leg still ran despite the refresh-leg error (best-effort).
	if res.SessionsDestroyed != 1 {
		t.Errorf("session leg did not run after a refresh-leg error: destroyed = %d, want 1", res.SessionsDestroyed)
	}
}

// --- ResolveLocalSubject format-mismatch branches (via the default resolver),
// the no-guess crux: a SET whose sub_id.format disagrees with the
// transmitter's configured subject mode maps to NOTHING. ---

func TestReceiver_OpaqueMode_IssSubFormatSubject_NoMap(t *testing.T) {
	t.Parallel()
	f := newRcvFixture(t) // opaque-mode transmitter
	now := time.Now()
	claims := map[string]any{
		"iss": rcvIssuer, "jti": "jti-fmt-mismatch", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"aud": []string{rcvAudience},
		// An iss_sub-FORMATTED subject sent to an OPAQUE transmitter ⇒ no guess.
		"sub_id": map[string]any{"format": "iss_sub", "iss": rcvIssuer, "sub": rcvLocalUser},
		"events": map[string]any{caep.EventURICAEPSessionRevoked: map[string]any{}},
	}
	set := f.signSET(t, claims)
	res, err := f.receiver.Receive(context.Background(), set)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if !res.Acked {
		t.Fatalf("a valid format-mismatched SET must be acked: %+v", res)
	}
	if res.Acted {
		t.Fatal("a format-mismatched subject was mapped+acted (wrong-guess)")
	}
	if !f.subjectHasAccess(t) {
		t.Fatal("a format-mismatched SET revoked the subject")
	}
}

func TestReceiver_OpaqueMode_EmptyID_NoMap(t *testing.T) {
	t.Parallel()
	f := newRcvFixture(t)
	now := time.Now()
	claims := map[string]any{
		"iss": rcvIssuer, "jti": "jti-empty-id", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"aud":    []string{rcvAudience},
		"sub_id": map[string]any{"format": "opaque", "id": ""}, // empty id ⇒ no map
		"events": map[string]any{caep.EventURICAEPSessionRevoked: map[string]any{}},
	}
	set := f.signSET(t, claims)
	res, err := f.receiver.Receive(context.Background(), set)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if res.Acted {
		t.Fatal("an empty opaque id mapped+acted")
	}
	if !f.subjectHasAccess(t) {
		t.Fatal("an empty-id SET revoked the subject")
	}
}

// --- iss_sub mode with an OPAQUE-formatted subject ⇒ no map (the inverse
// format-mismatch). Also covers the iss_sub empty-sub branch. ---

func TestReceiver_IssSubMode_OpaqueFormatSubject_NoMap(t *testing.T) {
	t.Parallel()
	f := newIssSubRcvFixture(t)
	now := time.Now()
	claims := map[string]any{
		"iss": rcvIssuer, "jti": "jti-isssub-opaque", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"aud": []string{rcvAudience},
		// opaque-FORMATTED subject sent to an ISS_SUB transmitter ⇒ no guess.
		"sub_id": map[string]any{"format": "opaque", "id": "upstream-sub-9"},
		"events": map[string]any{caep.EventURIRISCAccountDisabled: map[string]any{}},
	}
	tok := func() string {
		t.Helper()
		s, err := f.issuer.SignJWT(context.Background(), caep.SecurityEventTokenTyp, claims)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return s
	}()
	res, err := f.receiver.Receive(context.Background(), tok)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if res.Acted {
		t.Fatal("an opaque-format subject mapped+acted under an iss_sub transmitter")
	}
	if !f.fedHasSession(t) {
		t.Fatal("the federated subject was wrongly revoked via a format-mismatched SET")
	}
}
