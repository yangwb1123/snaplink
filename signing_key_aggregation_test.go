package sso_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/defaultimpl"
	signingkeysmemory "github.com/snaplink/sso/signingkeys/memory"
)

// serverJWKS collects the union of every wired issuer's JWKS the way the
// /jwks.json handler does — used to assert peer keys do (or don't) surface.
func serverJWKS(t *testing.T, s *sso.Server) []core.JWK {
	t.Helper()
	var out []core.JWK
	for _, ti := range s.TokenIssuers() {
		jp, ok := ti.(core.JWKSProvider)
		if !ok {
			continue
		}
		jwks, err := jp.JWKS(context.Background())
		if err != nil {
			t.Fatalf("JWKS: %v", err)
		}
		out = append(out, jwks...)
	}
	return out
}

func jwksHasKidSrv(jwks []core.JWK, kid string) bool {
	for _, k := range jwks {
		if k.Kid == kid {
			return true
		}
	}
	return false
}

// newAggServer builds a minimal Server with a single Ed25519 JWT issuer,
// wired into the shared signing-key registry under replicaID.
func newAggServer(t *testing.T, replicaID string, reg *signingkeysmemory.Registry) (*sso.Server, *defaultimpl.Ed25519JWTIssuer) {
	t.Helper()
	iss := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("https://sso.example"),
		defaultimpl.WithEd25519TokenTTL(5*time.Minute),
	)
	srv := sso.NewServer(
		sso.WithTokenIssuer(sso.TokenStrategyJWT, iss),
		sso.WithSharedSigningKeyRegistry(reg),
		sso.WithSigningKeyReplicaID(replicaID),
	)
	return srv, iss
}

// TestSigningKeyAggregation_CrossReplicaVerify is the end-to-end property:
// two Servers each holding their own Ed25519 key, sharing one in-memory
// registry. After aggregation settles, a token minted by A validates on B
// and A's kid appears in B's JWKS union (and vice versa).
func TestSigningKeyAggregation_CrossReplicaVerify(t *testing.T) {
	reg := signingkeysmemory.New()
	defer reg.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srvA, issA := newAggServer(t, "replica-a", reg)
	srvB, issB := newAggServer(t, "replica-b", reg)

	doneA, err := srvA.StartSigningKeyAggregation(ctx)
	if err != nil {
		t.Fatalf("start A: %v", err)
	}
	doneB, err := srvB.StartSigningKeyAggregation(ctx)
	if err != nil {
		t.Fatalf("start B: %v", err)
	}

	// A token minted by A.
	tokA, err := issA.Issue(ctx, &sso.Subject{ID: "user-a", ClientID: "c"}, []string{"read"})
	if err != nil {
		t.Fatalf("A Issue: %v", err)
	}

	// Eventual consistency: the registry fan-out + initial List run
	// synchronously inside StartSigningKeyAggregation, but the goroutine
	// that consumes the subscription stream is async. Poll briefly.
	if !waitFor(2*time.Second, func() bool {
		_, vErr := srvB.ValidateToken(ctx, tokA.AccessToken)
		return vErr == nil && jwksHasKidSrv(serverJWKS(t, srvB), issA.KeyID())
	}) {
		t.Fatalf("B never adopted A's key (kid=%s)", issA.KeyID())
	}

	// Symmetric: a token minted by B validates on A.
	tokB, err := issB.Issue(ctx, &sso.Subject{ID: "user-b", ClientID: "c"}, []string{"read"})
	if err != nil {
		t.Fatalf("B Issue: %v", err)
	}
	if !waitFor(2*time.Second, func() bool {
		_, vErr := srvA.ValidateToken(ctx, tokB.AccessToken)
		return vErr == nil && jwksHasKidSrv(serverJWKS(t, srvA), issB.KeyID())
	}) {
		t.Fatalf("A never adopted B's key (kid=%s)", issB.KeyID())
	}

	// A must NOT adopt its OWN key as a peer key (no duplicate kid).
	jwksA := serverJWKS(t, srvA)
	count := 0
	for _, k := range jwksA {
		if k.Kid == issA.KeyID() {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("A's own kid appears %d times in its JWKS, want 1", count)
	}

	cancel()
	reg.Close()
	<-doneA
	<-doneB
}

// TestSigningKeyAggregation_OptInByteIdentity is the single most important
// property: with NO registry wired the JWKS is byte-identical to a Server
// built without the option, and no peer keys are ever adopted (zero
// regression). StartSigningKeyAggregation is a no-op (already-closed chan,
// nil error).
func TestSigningKeyAggregation_OptInByteIdentity(t *testing.T) {
	// Same key on both so JWKS is comparable: byte-identity is about the
	// option not perturbing output, not about key material.
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://sso.example"))

	withoutOpt := sso.NewServer(sso.WithTokenIssuer(sso.TokenStrategyJWT, iss))
	withOptNoReg := sso.NewServer(
		sso.WithTokenIssuer(sso.TokenStrategyJWT, iss),
		// Wired but nil-default: the option is present, the registry is not.
		sso.WithSigningKeyReplicaID("replica-x"),
		sso.WithSigningKeyLeaseTTL(time.Minute),
	)

	// StartSigningKeyAggregation must be a pure no-op without a registry.
	done, err := withOptNoReg.StartSigningKeyAggregation(context.Background())
	if err != nil {
		t.Fatalf("StartSigningKeyAggregation no-op returned error: %v", err)
	}
	select {
	case <-done:
	default:
		t.Fatal("StartSigningKeyAggregation returned an un-closed channel without a registry")
	}

	a := serverJWKS(t, withoutOpt)
	b := serverJWKS(t, withOptNoReg)
	if len(a) != len(b) {
		t.Fatalf("JWKS length differs: without=%d withOpt=%d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("JWKS entry %d differs:\n without=%+v\n withOpt=%+v", i, a[i], b[i])
		}
	}

	// And the issuer's own JWKS carries exactly its one signing key — no
	// stray peer entries snuck in.
	own, _ := iss.JWKS(context.Background())
	if len(own) != 1 {
		t.Fatalf("issuer JWKS has %d keys without a registry, want 1 (peerVerifyKeys must be empty)", len(own))
	}
}

func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return cond()
}
