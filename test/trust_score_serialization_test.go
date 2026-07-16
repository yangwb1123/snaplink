package ssotest

// Drives interfaces/sso.WithTrustScoreSerialization end to end over a real
// Server (real memory user/client/session stores, a real Ed25519JWTIssuer, a
// real audit.MemorySink — no mocks, per AGENTS.md §0.5): a real /auth/login
// direct-mint round trip (response_type empty) proves the computed trust
// score is (a) stamped onto the login audit event's Metadata via
// audit.SetMeta when StampSessionMetadata is set, (b) added as a token claim
// via Subject.Claims when IncludeTokenClaim is set, and (c) that leaving
// both flags off (the default) is byte-identical to a build predating the
// feature — no claim, no metadata key.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/audit/auditspi"
	"github.com/snaplink/sso/shared/trust"
)

// errTSBadPassword / errTSScorerUnavailable are the two independent test
// failure reasons used below (wrong credential vs. a failing trust data
// source) — kept distinct so a test asserting one can't be confused for
// the other.
var (
	errTSBadPassword       = errors.New("bad password")
	errTSScorerUnavailable = errors.New("boom: trust data source unreachable")
)

const (
	tsUser     = "u-trust-score"
	tsClient   = "trust-score-client"
	tsPassword = "correct-horse"
)

// tsFixedScorer is a minimal real trust.TrustScorer implementation (not a
// mocking-library fake — the same shape as the SDK's own reference
// scorers) returning a deterministic value + reason trail, so the test can
// assert the exact serialized string.
type tsFixedScorer struct {
	value   float64
	reasons []string
}

func (tsFixedScorer) Name() string { return "fixed" }

func (s tsFixedScorer) Score(context.Context, trust.TrustSignals) (trust.TrustScore, error) {
	return trust.TrustScore{Value: s.value, Reasons: s.reasons}, nil
}

var _ trust.TrustScorer = tsFixedScorer{}

// tsHarness wires a real Server (password auth, memory session manager, a
// real Ed25519JWTIssuer usable both to mint AND to decode the returned
// access_token) plus a real audit.MemorySink.
type tsHarness struct {
	hs   *httptest.Server
	sink *audit.MemorySink
	iss  *defaultimpl.Ed25519JWTIssuer
}

func newTSHarness(t *testing.T, scorer trust.TrustScorer, serialCfg trust.SerializationConfig) *tsHarness {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: tsUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: tsClient, Secret: "ts-secret", Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p == tsPassword {
				return &sso.AuthResult{UserID: tsUser}, nil
			}
			return nil, errTSBadPassword
		},
	))
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	sink := audit.NewMemorySink(50)
	rec := audit.New(sink)

	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", iss),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuditRecorder(rec),
	}
	if scorer != nil {
		opts = append(opts, sso.WithTrustScorer(scorer))
	}
	opts = append(opts, sso.WithTrustScoreSerialization(serialCfg))

	srv := sso.NewServer(opts...)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return &tsHarness{hs: hs, sink: sink, iss: iss}
}

// login drives a direct-mint /auth/login (response_type empty) and returns
// the decoded JSON body.
func (h *tsHarness) login(t *testing.T) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  tsClient,
		"credential": map[string]string{"username": tsUser, "password": tsPassword},
	})
	resp, err := http.Post(h.hs.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /auth/login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/auth/login status = %d, body = %s", resp.StatusCode, raw)
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode /auth/login response: %v (body=%s)", err, raw)
	}
	return out
}

// loginEvent returns the single recorded EventLogin (success) event.
func (h *tsHarness) loginEvent(t *testing.T) *audit.Event {
	t.Helper()
	events, err := h.sink.Query(context.Background(), auditspi.Query{Type: audit.EventLogin, ActorID: tsUser})
	if err != nil {
		t.Fatalf("query login events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("login events = %d, want 1", len(events))
	}
	return events[0]
}

// TestTrustScoreSerialization_BothOff_ByteIdenticalToPreFeature proves the
// documented default-off contract: with StampSessionMetadata/IncludeTokenClaim
// both false (config's zero value), the login response, the minted token's
// claims, and the login audit event's Metadata are all untouched by this
// feature — even though a real TrustScorer IS wired (so the byte-identical
// behavior is coming from the serialization gate, not from an absent
// scorer).
func TestTrustScoreSerialization_BothOff_ByteIdenticalToPreFeature(t *testing.T) {
	t.Parallel()
	h := newTSHarness(t, tsFixedScorer{value: 0.77, reasons: []string{"fixed:always"}}, trust.SerializationConfig{})

	out := h.login(t)
	tok, _ := out["access_token"].(string)
	if tok == "" {
		t.Fatalf("empty access_token: %v", out)
	}
	claims, err := h.iss.Validate(context.Background(), tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if _, ok := claims.Extra["trust_score"]; ok {
		t.Errorf("trust_score claim present with serialization off: %v", claims.Extra)
	}

	evt := h.loginEvent(t)
	if _, ok := evt.Metadata["trust_score"]; ok {
		t.Errorf("trust_score metadata present with serialization off: %v", evt.Metadata)
	}
	if _, ok := evt.Metadata["trust_reasons"]; ok {
		t.Errorf("trust_reasons metadata present with serialization off: %v", evt.Metadata)
	}
}

// TestTrustScoreSerialization_TokenClaimWired proves IncludeTokenClaim (with
// a custom ClaimName) lands the formatted score as a claim on the minted
// direct-mint access token, while StampSessionMetadata stays off (no
// metadata key added) — the two flags are independently switchable.
func TestTrustScoreSerialization_TokenClaimWired(t *testing.T) {
	t.Parallel()
	h := newTSHarness(t, tsFixedScorer{value: 0.5}, trust.SerializationConfig{
		IncludeTokenClaim: true,
		ClaimName:         "zt_trust",
	})

	out := h.login(t)
	tok, _ := out["access_token"].(string)
	claims, err := h.iss.Validate(context.Background(), tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := claims.Extra["zt_trust"]; got != "0.50" {
		t.Errorf("zt_trust claim = %q, want %q", got, "0.50")
	}

	evt := h.loginEvent(t)
	if _, ok := evt.Metadata["trust_score"]; ok {
		t.Errorf("trust_score metadata present with StampSessionMetadata off: %v", evt.Metadata)
	}
}

// TestTrustScoreSerialization_SessionMetadataWired proves
// StampSessionMetadata stamps the score + reasons onto the SAME login audit
// event via SetMeta (never a second event), while IncludeTokenClaim stays
// off (no token claim added).
func TestTrustScoreSerialization_SessionMetadataWired(t *testing.T) {
	t.Parallel()
	h := newTSHarness(t, tsFixedScorer{value: 0.9, reasons: []string{"geo_risk:known_country", "behavior:cold_start"}},
		trust.SerializationConfig{StampSessionMetadata: true})

	out := h.login(t)
	tok, _ := out["access_token"].(string)
	claims, err := h.iss.Validate(context.Background(), tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if _, ok := claims.Extra["trust_score"]; ok {
		t.Errorf("trust_score claim present with IncludeTokenClaim off: %v", claims.Extra)
	}

	evt := h.loginEvent(t)
	if got := evt.Metadata["trust_score"]; got != "0.90" {
		t.Errorf("trust_score metadata = %q, want %q", got, "0.90")
	}
	if got, want := evt.Metadata["trust_reasons"], "geo_risk:known_country,behavior:cold_start"; got != want {
		t.Errorf("trust_reasons metadata = %q, want %q", got, want)
	}
	// Exactly one login event — metadata rides the SAME event, never a
	// second audit record.
	all, _ := h.sink.Query(context.Background(), auditspi.Query{ActorID: tsUser})
	if len(all) != 1 {
		t.Fatalf("total audit events for actor = %d, want 1 (metadata must not create a second event)", len(all))
	}
}

// TestTrustScoreSerialization_BothWired_SameScoreBothSinks proves a single
// Score() call result is threaded consistently into both the token claim
// AND the session metadata — not two independent (and potentially
// disagreeing, for a non-deterministic scorer) calls.
func TestTrustScoreSerialization_BothWired_SameScoreBothSinks(t *testing.T) {
	t.Parallel()
	h := newTSHarness(t, tsFixedScorer{value: 0.33}, trust.SerializationConfig{
		StampSessionMetadata: true,
		IncludeTokenClaim:    true,
	})

	out := h.login(t)
	tok, _ := out["access_token"].(string)
	claims, err := h.iss.Validate(context.Background(), tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	claimVal := claims.Extra["trust_score"]
	if claimVal != "0.33" {
		t.Fatalf("token trust_score claim = %q, want %q", claimVal, "0.33")
	}

	evt := h.loginEvent(t)
	if evt.Metadata["trust_score"] != claimVal {
		t.Errorf("metadata trust_score %q != token claim trust_score %q", evt.Metadata["trust_score"], claimVal)
	}
}

// TestTrustScoreSerialization_ScorerErrorFailsOpen proves a scorer error
// never blocks the login and never serializes a bogus score — the login
// still succeeds and carries neither the claim nor the metadata key.
func TestTrustScoreSerialization_ScorerErrorFailsOpen(t *testing.T) {
	t.Parallel()
	h := newTSHarness(t, tsErroringScorer{}, trust.SerializationConfig{
		StampSessionMetadata: true,
		IncludeTokenClaim:    true,
	})

	out := h.login(t) // must not fail/500 despite the scorer erroring.
	tok, _ := out["access_token"].(string)
	if tok == "" {
		t.Fatalf("login must still succeed on scorer error: %v", out)
	}
	claims, err := h.iss.Validate(context.Background(), tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if _, ok := claims.Extra["trust_score"]; ok {
		t.Errorf("trust_score claim must be absent when the scorer errors: %v", claims.Extra)
	}
	evt := h.loginEvent(t)
	if _, ok := evt.Metadata["trust_score"]; ok {
		t.Errorf("trust_score metadata must be absent when the scorer errors: %v", evt.Metadata)
	}
}

// TestTrustScoreSerialization_NoScorerWiredIsNoOp proves the flags alone
// (with no WithTrustScorer at all) add nothing — resolveLoginTrustScore
// must short-circuit before ever touching a nil scorer.
func TestTrustScoreSerialization_NoScorerWiredIsNoOp(t *testing.T) {
	t.Parallel()
	h := newTSHarness(t, nil, trust.SerializationConfig{
		StampSessionMetadata: true,
		IncludeTokenClaim:    true,
	})

	out := h.login(t)
	tok, _ := out["access_token"].(string)
	claims, err := h.iss.Validate(context.Background(), tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if _, ok := claims.Extra["trust_score"]; ok {
		t.Errorf("trust_score claim present with no scorer wired: %v", claims.Extra)
	}
	evt := h.loginEvent(t)
	if _, ok := evt.Metadata["trust_score"]; ok {
		t.Errorf("trust_score metadata present with no scorer wired: %v", evt.Metadata)
	}
}

type tsErroringScorer struct{}

func (tsErroringScorer) Name() string { return "erroring" }
func (tsErroringScorer) Score(context.Context, trust.TrustSignals) (trust.TrustScore, error) {
	return trust.TrustScore{}, errTSScorerUnavailable
}

var _ trust.TrustScorer = tsErroringScorer{}
