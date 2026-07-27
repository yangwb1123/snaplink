package cryptoinventory

import (
	"context"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

// fakeJWKSIssuer is a minimal core.JWKSProvider + keyRetirer + keyDropper
// test double standing in for a real signing-key TokenIssuer
// (Ed25519JWTIssuer/ECDSAJWTIssuer/RSAJWTIssuer), which this package cannot
// import directly — infrastructure is a higher layer (AGENTS.md §0.2).
type fakeJWKSIssuer struct {
	jwks        []core.JWK
	retiredKids []string
	droppedKids []string
}

func (f *fakeJWKSIssuer) Issue(context.Context, *core.Subject, []string) (*core.Token, error) {
	return nil, nil
}
func (f *fakeJWKSIssuer) Validate(context.Context, string) (*core.TokenClaims, error) {
	return nil, nil
}
func (f *fakeJWKSIssuer) Revoke(context.Context, string) error { return nil }

func (f *fakeJWKSIssuer) JWKS(context.Context) ([]core.JWK, error) { return f.jwks, nil }

func (f *fakeJWKSIssuer) RetireKey(kid string) error {
	f.retiredKids = append(f.retiredKids, kid)
	return nil
}

func (f *fakeJWKSIssuer) DropVerifyKey(kid string) {
	f.droppedKids = append(f.droppedKids, kid)
}

var _ core.TokenIssuer = (*fakeJWKSIssuer)(nil)
var _ core.JWKSProvider = (*fakeJWKSIssuer)(nil)
var _ keyRetirer = (*fakeJWKSIssuer)(nil)
var _ keyDropper = (*fakeJWKSIssuer)(nil)

// symmetricIssuer implements core.TokenIssuer but NOT core.JWKSProvider —
// exercising JWKSSource's "skip issuers that aren't publicly verifiable"
// behavior, mirroring the real JWKS endpoint's own aggregation.
type symmetricIssuer struct{}

func (symmetricIssuer) Issue(context.Context, *core.Subject, []string) (*core.Token, error) {
	return nil, nil
}
func (symmetricIssuer) Validate(context.Context, string) (*core.TokenClaims, error) {
	return nil, nil
}
func (symmetricIssuer) Revoke(context.Context, string) error { return nil }

var _ core.TokenIssuer = symmetricIssuer{}

func TestJWKSSource_Keys(t *testing.T) {
	iss := &fakeJWKSIssuer{jwks: []core.JWK{
		{Kid: "kid-1", Kty: "OKP", Alg: "EdDSA"},
		{Kid: "kid-2", Kty: "RSA", Alg: "RS256", Use: "enc"},
	}}
	src := &JWKSSource{Issuers: map[string]core.TokenIssuer{
		"access_token": iss,
		"opaque":       symmetricIssuer{},
	}}

	entries, err := src.Keys(context.Background())
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("Keys() returned %d entries, want 2 (symmetric issuer skipped): %+v", len(entries), entries)
	}

	byKid := map[string]Entry{}
	for _, e := range entries {
		byKid[e.KeyID] = e
	}
	if byKid["kid-1"].Purpose != PurposeSign {
		t.Errorf("kid-1 Purpose = %q, want sign", byKid["kid-1"].Purpose)
	}
	if byKid["kid-2"].Purpose != PurposeEncrypt {
		t.Errorf("kid-2 Purpose = %q, want encrypt (use=enc)", byKid["kid-2"].Purpose)
	}
	if byKid["kid-1"].BackingStore != "memory" {
		t.Errorf("BackingStore = %q, want default memory", byKid["kid-1"].BackingStore)
	}
	if byKid["kid-1"].Status != StatusActive {
		t.Errorf("Status = %q, want active (JWKS wire format has no status field)", byKid["kid-1"].Status)
	}
}

func TestJWKSSource_RetireKey_TriesBothSeams(t *testing.T) {
	owner := &fakeJWKSIssuer{}
	peer := &fakeJWKSIssuer{}
	src := &JWKSSource{Issuers: map[string]core.TokenIssuer{
		"owner": owner,
		"peer":  peer,
	}}

	if err := src.RetireKey(context.Background(), "kid-1"); err != nil {
		t.Fatalf("RetireKey: %v", err)
	}
	// Best-effort: both RetireKey and DropVerifyKey are tried on EVERY
	// issuer (mirrors interfaces/sso.runCoordinatedRetire) — most calls are
	// harmless no-ops on an issuer that doesn't actually hold the kid.
	if len(owner.retiredKids) != 1 || owner.retiredKids[0] != "kid-1" {
		t.Errorf("owner.retiredKids = %v", owner.retiredKids)
	}
	if len(owner.droppedKids) != 1 || owner.droppedKids[0] != "kid-1" {
		t.Errorf("owner.droppedKids = %v", owner.droppedKids)
	}
	if len(peer.retiredKids) != 1 || len(peer.droppedKids) != 1 {
		t.Errorf("peer retire/drop not attempted: retired=%v dropped=%v", peer.retiredKids, peer.droppedKids)
	}
}
