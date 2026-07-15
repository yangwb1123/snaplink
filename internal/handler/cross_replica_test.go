package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/cluster"
	clustermem "github.com/snaplink/sso/platform/cluster/memory"
	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/shared/spi"
)

// makeJWT builds a compact JWT whose payload carries the given exp. The
// signature segment is a placeholder — JWTExpUnsafe never verifies it.
func makeJWT(t *testing.T, exp int64) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload, err := json.Marshal(struct {
		Exp int64 `json:"exp"`
	}{Exp: exp})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	return header + "." + body + ".sig"
}

// TestJWTExpUnsafe locks the unverified exp extraction: a well-formed JWT yields
// its exp, and any malformed shape (wrong segment count, bad base64, non-JSON,
// opaque token) yields 0 so the caller treats it as "no advisory exp".
func TestJWTExpUnsafe(t *testing.T) {
	t.Parallel()
	good := makeJWT(t, 1893456000)
	cases := []struct {
		name  string
		token string
		want  int64
	}{
		{"valid jwt", good, 1893456000},
		{"opaque token", "opaque", 0},
		{"two segments", "aaa.bbb", 0},
		{"four segments", "a.b.c.d", 0},
		{"bad base64 payload", "aaa.!!!.ccc", 0},
		{"non-json payload", "aaa." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".ccc", 0},
		{"empty", "", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := JWTExpUnsafe(c.token); got != c.want {
				t.Fatalf("JWTExpUnsafe(%q) = %d, want %d", c.token, got, c.want)
			}
		})
	}
}

// makeClaimsJWT builds a compact JWT whose payload carries client_id + sub —
// the two claims JWTClaimsUnsafe extracts for the token_revoked audit event
// (see audit.RecordTokenRevoked). Signature segment is a placeholder;
// JWTClaimsUnsafe never verifies it (advisory-only, mirrors JWTExpUnsafe).
func makeClaimsJWT(t *testing.T, clientID, sub string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload, err := json.Marshal(struct {
		ClientID string `json:"client_id"`
		Sub      string `json:"sub"`
	}{ClientID: clientID, Sub: sub})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	return header + "." + body + ".sig"
}

// TestJWTClaimsUnsafe locks the unverified client_id/sub extraction: a
// well-formed JWT yields both claims, and any malformed shape yields two
// empty strings rather than an error — a decode failure must never block the
// token_revoked audit record that consumes this.
func TestJWTClaimsUnsafe(t *testing.T) {
	t.Parallel()
	good := makeClaimsJWT(t, "client-1", "user-1")
	cases := []struct {
		name        string
		token       string
		wantClient  string
		wantSubject string
	}{
		{"valid jwt", good, "client-1", "user-1"},
		{"opaque token", "opaque", "", ""},
		{"two segments", "aaa.bbb", "", ""},
		{"four segments", "a.b.c.d", "", ""},
		{"bad base64 payload", "aaa.!!!.ccc", "", ""},
		{"non-json payload", "aaa." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".ccc", "", ""},
		{"empty", "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotClient, gotSubject := JWTClaimsUnsafe(c.token)
			if gotClient != c.wantClient || gotSubject != c.wantSubject {
				t.Fatalf("JWTClaimsUnsafe(%q) = (%q, %q), want (%q, %q)",
					c.token, gotClient, gotSubject, c.wantClient, c.wantSubject)
			}
		})
	}
}

// TestPublishTokenRevocation_WireFormat is the centerpiece wire-contract guard.
// A real in-memory cluster.Bus subscriber must receive a KindTokenRevoked Event
// whose Payload carries the FULL token under MetaRevokedToken and the advisory
// exp under MetaRevokedExp, and the published metric must increment.
func TestPublishTokenRevocation_WireFormat(t *testing.T) {
	t.Parallel()
	bus := clustermem.New()
	defer func() { _ = bus.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sub, err := bus.Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	m := metrics.New()
	d := &ServerDeps{
		Logger:                 spi.NopLogger{},
		Metrics:                m,
		CrossReplicaRevocation: true,
		InvalidationBus:        bus,
	}

	const token = "header.payload.sig"
	const exp = int64(1893456000)
	PublishTokenRevocation(d, ctx, token, exp)

	select {
	case evt := <-sub:
		if evt.Kind != cluster.KindTokenRevoked {
			t.Fatalf("evt.Kind = %q, want %q", evt.Kind, cluster.KindTokenRevoked)
		}
		if got := evt.Payload[cluster.MetaRevokedToken]; got != token {
			t.Fatalf("Payload[%s] = %q, want %q", cluster.MetaRevokedToken, got, token)
		}
		if got := evt.Payload[cluster.MetaRevokedExp]; got != strconv.FormatInt(exp, 10) {
			t.Fatalf("Payload[%s] = %q, want %q", cluster.MetaRevokedExp, got, strconv.FormatInt(exp, 10))
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for published revocation Event")
	}

	if got := counterValue(t, m, metrics.RevocationDirectionPublished); got != 1 {
		t.Fatalf("published counter = %v, want 1", got)
	}
}

// TestPublishTokenRevocation_Disabled covers the guard: with cross-replica
// revocation off, nothing is published.
func TestPublishTokenRevocation_Disabled(t *testing.T) {
	t.Parallel()
	bus := clustermem.New()
	defer func() { _ = bus.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sub, err := bus.Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	d := &ServerDeps{
		Logger:                 spi.NopLogger{},
		Metrics:                metrics.New(),
		CrossReplicaRevocation: false, // disabled
		InvalidationBus:        bus,
	}
	PublishTokenRevocation(d, ctx, "header.payload.sig", 1)
	select {
	case evt := <-sub:
		t.Fatalf("disabled cross-replica revocation must not publish, got %+v", evt)
	case <-time.After(50 * time.Millisecond):
		// expected: no event
	}
}

// TestPublishTokenRevocation_NilBusAndEmptyToken covers the remaining guards:
// a nil bus and an empty token are silent no-ops (no panic).
func TestPublishTokenRevocation_NilBusAndEmptyToken(t *testing.T) {
	t.Parallel()
	d := &ServerDeps{
		Logger:                 spi.NopLogger{},
		Metrics:                metrics.New(),
		CrossReplicaRevocation: true,
		InvalidationBus:        nil, // nil bus
	}
	// Must not panic.
	PublishTokenRevocation(d, context.Background(), "header.payload.sig", 1)

	bus := clustermem.New()
	defer func() { _ = bus.Close() }()
	d.InvalidationBus = bus
	PublishTokenRevocation(d, context.Background(), "", 1) // empty token
}

// TestPublishTokenRevocation_FailOpenOnBusError covers the fail-open contract:
// a publish error against a closed bus is logged and swallowed (no panic), and
// the published metric is NOT incremented.
func TestPublishTokenRevocation_FailOpenOnBusError(t *testing.T) {
	t.Parallel()
	bus := clustermem.New()
	_ = bus.Close() // Publish now returns ErrClosed
	m := metrics.New()
	d := &ServerDeps{
		Logger:                 spi.NopLogger{},
		Metrics:                m,
		CrossReplicaRevocation: true,
		InvalidationBus:        bus,
	}
	PublishTokenRevocation(d, context.Background(), "header.payload.sig", 1)
	if got := counterValue(t, m, metrics.RevocationDirectionPublished); got != 0 {
		t.Fatalf("published counter = %v, want 0 (publish failed)", got)
	}
}

// TestApplyTokenRevocation_AdoptsAndCounts covers the subscriber arm: a valid
// KindTokenRevoked Event routes the carried token to the LOCAL revoke seam and,
// on a non-empty revoked result, increments the adopted metric.
func TestApplyTokenRevocation_AdoptsAndCounts(t *testing.T) {
	t.Parallel()
	m := metrics.New()
	var gotToken string
	d := &ServerDeps{
		Logger:                 spi.NopLogger{},
		Metrics:                m,
		CrossReplicaRevocation: true,
		RevokeAcrossIssuers: func(_ context.Context, token string) ([]string, []string) {
			gotToken = token
			return []string{"https://issuer.example"}, nil // one issuer revoked it
		},
	}
	evt := cluster.Event{
		Kind:    cluster.KindTokenRevoked,
		Payload: map[string]string{cluster.MetaRevokedToken: "header.payload.sig"},
	}
	ApplyTokenRevocation(d, context.Background(), evt)

	if gotToken != "header.payload.sig" {
		t.Fatalf("token routed to revoke seam = %q, want header.payload.sig", gotToken)
	}
	if got := counterValue(t, m, metrics.RevocationDirectionAdopted); got != 1 {
		t.Fatalf("adopted counter = %v, want 1", got)
	}
}

// TestApplyTokenRevocation_NilMetricsNoPanic locks the nil-Metrics guard: a
// successful adoption with Metrics unwired must NOT panic.
func TestApplyTokenRevocation_NilMetricsNoPanic(t *testing.T) {
	t.Parallel()
	d := &ServerDeps{
		Logger:                 spi.NopLogger{},
		Metrics:                nil, // unwired
		CrossReplicaRevocation: true,
		RevokeAcrossIssuers: func(context.Context, string) ([]string, []string) {
			return []string{"https://issuer.example"}, nil
		},
	}
	evt := cluster.Event{
		Kind:    cluster.KindTokenRevoked,
		Payload: map[string]string{cluster.MetaRevokedToken: "header.payload.sig"},
	}
	// The assertion is "does not panic"; reaching the next line proves it.
	ApplyTokenRevocation(d, context.Background(), evt)
}

// TestApplyTokenRevocation_NoOpPaths covers every early-return: disabled,
// wrong event kind, empty token, and a token no local issuer owns (revoked is
// empty -> no adopted count). None of these may route to revoke (except the
// last, where revoke runs but the metric stays at 0).
func TestApplyTokenRevocation_NoOpPaths(t *testing.T) {
	t.Parallel()
	t.Run("disabled is a no-op", func(t *testing.T) {
		called := false
		d := newApplyDeps(&called, []string{"x"})
		d.CrossReplicaRevocation = false
		ApplyTokenRevocation(d, context.Background(), revokedEvent("tok"))
		if called {
			t.Fatal("disabled must not route to revoke")
		}
	})

	t.Run("wrong kind is a no-op", func(t *testing.T) {
		called := false
		d := newApplyDeps(&called, []string{"x"})
		evt := cluster.Event{Kind: cluster.KindClientChange, Payload: map[string]string{cluster.MetaRevokedToken: "tok"}}
		ApplyTokenRevocation(d, context.Background(), evt)
		if called {
			t.Fatal("non-revoked event kind must not route to revoke")
		}
	})

	t.Run("empty token is a no-op", func(t *testing.T) {
		called := false
		d := newApplyDeps(&called, []string{"x"})
		ApplyTokenRevocation(d, context.Background(), revokedEvent(""))
		if called {
			t.Fatal("empty token must not route to revoke")
		}
	})

	t.Run("unknown token revokes but counts nothing", func(t *testing.T) {
		called := false
		m := metrics.New()
		d := newApplyDeps(&called, nil) // revoke returns empty: no issuer owned it
		d.Metrics = m
		ApplyTokenRevocation(d, context.Background(), revokedEvent("tok"))
		if !called {
			t.Fatal("a foreign-but-well-formed event still asks every local issuer")
		}
		if got := counterValue(t, m, metrics.RevocationDirectionAdopted); got != 0 {
			t.Fatalf("adopted counter = %v, want 0 (nothing locally revoked)", got)
		}
	})
}

func newApplyDeps(called *bool, revoked []string) *ServerDeps {
	return &ServerDeps{
		Logger:                 spi.NopLogger{},
		Metrics:                metrics.New(),
		CrossReplicaRevocation: true,
		RevokeAcrossIssuers: func(context.Context, string) ([]string, []string) {
			*called = true
			return revoked, nil
		},
	}
}

func revokedEvent(token string) cluster.Event {
	return cluster.Event{
		Kind:    cluster.KindTokenRevoked,
		Payload: map[string]string{cluster.MetaRevokedToken: token},
	}
}

// counterValue reads the current value of the propagation counter for a given
// direction label off the real metrics.Metrics via its own registry's Gather
// (core client_golang — matches the repo's no-testutil convention). Returns 0
// when the series has not been touched.
func counterValue(t *testing.T, m *metrics.Metrics, direction string) float64 {
	t.Helper()
	mfs, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != metrics.NameTokenRevocationsPropagatedTotal {
			continue
		}
		for _, metric := range mf.GetMetric() {
			for _, lp := range metric.GetLabel() {
				if lp.GetName() == metrics.LabelDirection && lp.GetValue() == direction {
					return metric.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}
