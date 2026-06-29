package federation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/federation"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/shared/core"
)

// ===========================================================================
// A FAKE federation (no real network). Each entity is a real Ed25519 issuer
// (its own keypair → distinct kid; JWKS() is its published key set). Entity
// Configurations + Subordinate Statements are signed via the real SignJWT seam
// (typ entity-statement+jwt). A fakeFetcher serves them. The clock is FIXED and
// injected into BOTH the synthesized statement exp/iat AND the resolver's
// validator, so exp is deterministic (no real-clock-vs-fixed date bomb).
// ===========================================================================

// fedClock is the single fixed instant the whole test federation is minted +
// validated against. Far in the past so it is never a real date bomb.
var fedClock = time.Unix(1_900_000_000, 0).UTC()

// fedEntity is one entity in the test federation: its id + its signing issuer.
type fedEntity struct {
	id  string
	iss *defaultimpl.Ed25519JWTIssuer
}

func newFedEntity(t *testing.T, id string) *fedEntity {
	t.Helper()
	return &fedEntity{id: id, iss: defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(id))}
}

// keys returns the entity's published JWKS (its own signing public keys).
func (e *fedEntity) keys(t *testing.T) []core.JWK {
	t.Helper()
	ks, err := e.iss.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS(%s): %v", e.id, err)
	}
	return ks
}

// signStatement signs an EntityStatementClaims as an entity-statement+jwt via
// the entity's issuer.
func (e *fedEntity) signStatement(t *testing.T, claims federation.EntityStatementClaims) string {
	t.Helper()
	compact, err := e.iss.SignJWT(context.Background(), federation.EntityStatementTyp, claims)
	if err != nil {
		t.Fatalf("SignJWT(%s): %v", e.id, err)
	}
	return compact
}

// entityConfig builds + signs `e`'s self-signed Entity Configuration. hints are
// its authority_hints; fetchEndpoint (when non-empty) is published in
// metadata.federation_entity (so `e` can serve subordinate statements as a
// superior). rp (when non-nil) is its openid_relying_party metadata (leaf RP).
func (e *fedEntity) entityConfig(t *testing.T, hints []string, fetchEndpoint string, rp map[string]any) string {
	t.Helper()
	meta := &federation.EntityMetadata{}
	if fetchEndpoint != "" {
		meta.FederationEntity = &federation.FederationEntityMeta{FederationFetchEndpoint: fetchEndpoint}
	}
	if rp != nil {
		meta.RP = rp
	}
	claims := federation.EntityStatementClaims{
		Iss:            e.id,
		Sub:            e.id,
		Iat:            fedClock.Unix(),
		Exp:            fedClock.Add(24 * time.Hour).Unix(),
		JWKS:           federation.EntityJWKS{Keys: e.keys(t)},
		Metadata:       meta,
		AuthorityHints: hints,
	}
	return e.signStatement(t, claims)
}

// subordinateStatement builds + signs the Subordinate Statement `e` (a
// superior) issues ABOUT subject: iss=e, sub=subject, jwks = subject's keys
// (the keys `e` vouches for subject), optional metadata_policy.
func (e *fedEntity) subordinateStatement(t *testing.T, subject *fedEntity, policy map[string]map[string]map[string]any) string {
	t.Helper()
	claims := federation.EntityStatementClaims{
		Iss:            e.id,
		Sub:            subject.id,
		Iat:            fedClock.Unix(),
		Exp:            fedClock.Add(24 * time.Hour).Unix(),
		JWKS:           federation.EntityJWKS{Keys: subject.keys(t)},
		MetadataPolicy: policy,
	}
	return e.signStatement(t, claims)
}

// fakeFetcher serves the test federation's documents in-memory.
type fakeFetcher struct {
	configs map[string]string // entityID -> signed Entity Configuration
	subs    map[string]string // "endpoint|iss|sub" -> signed Subordinate Statement
	calls   int               // total fetch calls (loop/DoS bound proof)
	fail    map[string]error  // entityID/key -> forced error (transport simulation)
}

func newFakeFetcher() *fakeFetcher {
	return &fakeFetcher{configs: map[string]string{}, subs: map[string]string{}, fail: map[string]error{}}
}

func subKey(endpoint, iss, sub string) string { return endpoint + "|" + iss + "|" + sub }

func (f *fakeFetcher) FetchEntityConfiguration(_ context.Context, entityID string) ([]byte, error) {
	f.calls++
	if err, ok := f.fail[entityID]; ok {
		return nil, err
	}
	c, ok := f.configs[entityID]
	if !ok {
		return nil, errors.New("fake: no entity configuration for " + entityID)
	}
	return []byte(c), nil
}

func (f *fakeFetcher) FetchSubordinateStatement(_ context.Context, endpoint, iss, sub string) ([]byte, error) {
	f.calls++
	k := subKey(endpoint, iss, sub)
	if err, ok := f.fail[k]; ok {
		return nil, err
	}
	s, ok := f.subs[k]
	if !ok {
		return nil, errors.New("fake: no subordinate statement for " + k)
	}
	return []byte(s), nil
}

// resolverFor builds a resolver wired to the fake fetcher + the fixed clock,
// with `anchor` as the single configured trust anchor (its configured Keys =
// the anchor's published JWKS, the root of trust).
func resolverFor(t *testing.T, fetcher federation.EntityStatementFetcher, anchor *fedEntity, opts ...federation.TrustChainResolverOption) *federation.TrustChainResolver {
	t.Helper()
	cfg := &federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: anchor.id, Keys: anchor.keys(t)}},
	}
	base := []federation.TrustChainResolverOption{
		federation.WithTrustChainFetcher(fetcher),
		federation.WithTrustChainClock(func() time.Time { return fedClock }),
	}
	return federation.NewTrustChainResolver(cfg, append(base, opts...)...)
}

const (
	tcAnchorID = "https://anchor.federation.test"
	tcInterID  = "https://intermediate.federation.test"
	tcLeafID   = "https://rp.federation.test"
	tcFetchURL = "https://anchor.federation.test/fetch"
	tcInterFch = "https://intermediate.federation.test/fetch"
)

// buildLinearFederation wires anchor -> intermediate -> leaf with the given
// leaf RP metadata + the anchor's metadata_policy about the intermediate (and
// the intermediate's about the leaf). Returns the fetcher + the entities.
func buildLinearFederation(t *testing.T, leafRP map[string]any, anchorPolicy, interPolicy map[string]map[string]map[string]any) (*fakeFetcher, *fedEntity, *fedEntity, *fedEntity) {
	t.Helper()
	anchor := newFedEntity(t, tcAnchorID)
	inter := newFedEntity(t, tcInterID)
	leaf := newFedEntity(t, tcLeafID)

	f := newFakeFetcher()
	// Entity Configurations (self-signed).
	f.configs[anchor.id] = anchor.entityConfig(t, nil, tcFetchURL, nil)
	f.configs[inter.id] = inter.entityConfig(t, []string{anchor.id}, tcInterFch, nil)
	f.configs[leaf.id] = leaf.entityConfig(t, []string{inter.id}, "", leafRP)
	// Subordinate Statements: anchor about intermediate, intermediate about leaf.
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = anchor.subordinateStatement(t, inter, anchorPolicy)
	f.subs[subKey(tcInterFch, inter.id, leaf.id)] = inter.subordinateStatement(t, leaf, interPolicy)
	return f, anchor, inter, leaf
}

// ===========================================================================
// HAPPY PATH
// ===========================================================================

func TestResolveTrustChain_HappyPath(t *testing.T) {
	t.Parallel()
	f, anchor, _, leaf := buildLinearFederation(t, map[string]any{
		"client_name":   "Test RP",
		"redirect_uris": []any{"https://rp.federation.test/cb"},
	}, nil, nil)

	r := resolverFor(t, f, anchor)
	chain, err := r.ResolveTrustChain(context.Background(), leaf.id)
	if err != nil {
		t.Fatalf("ResolveTrustChain: %v", err)
	}
	if chain.LeafEntityID != leaf.id {
		t.Errorf("LeafEntityID = %q, want %q", chain.LeafEntityID, leaf.id)
	}
	if chain.AnchorEntityID != anchor.id {
		t.Errorf("AnchorEntityID = %q, want the configured anchor %q", chain.AnchorEntityID, anchor.id)
	}
	// Canonical chain (intermediates' own configs are NOT validated links):
	// [leafConfig, SS(inter->leaf), SS(anchor->inter), anchorConfig] = 4.
	if len(chain.Statements) != 4 {
		t.Errorf("chain length = %d, want 4", len(chain.Statements))
	}
	if chain.ResolvedRPMetadata["client_name"] != "Test RP" {
		t.Errorf("resolved RP client_name = %v, want Test RP", chain.ResolvedRPMetadata["client_name"])
	}
}

// TestResolveTrustChain_LeafNotSelfIssuedForRequestedID_Rejected guards OpenID
// Federation §9: the Entity Configuration fetched from the requested leaf URL
// MUST be self-issued FOR that id (iss==sub==leafEntityID). A member that can
// host a well-known at the leaf URL but serves a config naming a DIFFERENT,
// legitimately-chained entity must be REJECTED — otherwise it could auto-register
// an OAuth client under any client_id URL it controls.
func TestResolveTrustChain_LeafNotSelfIssuedForRequestedID_Rejected(t *testing.T) {
	t.Parallel()
	f, anchor, inter, leaf := buildLinearFederation(t, map[string]any{
		"client_name":   "Impostor RP",
		"redirect_uris": []any{"https://rp.federation.test/cb"},
	}, nil, nil)

	// At the leaf's well-known URL, serve a config self-issued for a DIFFERENT id.
	impostor := newFedEntity(t, "https://impostor.federation.test")
	f.configs[leaf.id] = impostor.entityConfig(t, []string{inter.id}, "",
		map[string]any{"client_name": "Impostor RP"})

	r := resolverFor(t, f, anchor)
	if _, err := r.ResolveTrustChain(context.Background(), leaf.id); err == nil {
		t.Fatal("ResolveTrustChain accepted a leaf config not self-issued for the requested entity id")
	}
}

func TestResolveTrustChain_DirectAnchorChild(t *testing.T) {
	t.Parallel()
	// A leaf whose immediate superior IS the configured anchor (2-hop chain).
	anchor := newFedEntity(t, tcAnchorID)
	leaf := newFedEntity(t, tcLeafID)
	f := newFakeFetcher()
	f.configs[anchor.id] = anchor.entityConfig(t, nil, tcFetchURL, nil)
	f.configs[leaf.id] = leaf.entityConfig(t, []string{anchor.id}, "", map[string]any{"client_name": "Direct"})
	f.subs[subKey(tcFetchURL, anchor.id, leaf.id)] = anchor.subordinateStatement(t, leaf, nil)

	r := resolverFor(t, f, anchor)
	chain, err := r.ResolveTrustChain(context.Background(), leaf.id)
	if err != nil {
		t.Fatalf("ResolveTrustChain: %v", err)
	}
	// leaf-first: [leafConfig, sub(anchor->leaf), anchorConfig] = 3
	if len(chain.Statements) != 3 {
		t.Errorf("chain length = %d, want 3", len(chain.Statements))
	}
}

// ===========================================================================
// FORGERY / UNTRUSTED-ANCHOR (the key security proofs)
// ===========================================================================

// TestResolveTrustChain_LeafSignedByUntrustedKey: the leaf's config is signed
// by a DIFFERENT key than the one the immediate superior vouches for. The
// signature against the superior-published keys must FAIL → rejected.
func TestResolveTrustChain_LeafSignedByUntrustedKey(t *testing.T) {
	t.Parallel()
	anchor := newFedEntity(t, tcAnchorID)
	inter := newFedEntity(t, tcInterID)
	leaf := newFedEntity(t, tcLeafID)
	attacker := newFedEntity(t, tcLeafID) // same id, DIFFERENT key

	f := newFakeFetcher()
	f.configs[anchor.id] = anchor.entityConfig(t, nil, tcFetchURL, nil)
	f.configs[inter.id] = inter.entityConfig(t, []string{anchor.id}, tcInterFch, nil)
	// The leaf CONFIG is signed by the attacker's key...
	f.configs[leaf.id] = attacker.entityConfig(t, []string{inter.id}, "", map[string]any{"client_name": "Evil"})
	// ...but the intermediate vouches for the LEGITIMATE leaf's keys.
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = anchor.subordinateStatement(t, inter, nil)
	f.subs[subKey(tcInterFch, inter.id, leaf.id)] = inter.subordinateStatement(t, leaf, nil)

	r := resolverFor(t, f, anchor)
	_, err := r.ResolveTrustChain(context.Background(), leaf.id)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("forged leaf signature: err = %v, want ErrTrustChainInvalid", err)
	}
}

// TestResolveTrustChain_AnchorConfigForged: the FETCHED anchor configuration is
// signed by an attacker key (not the CONFIGURED anchor keys). The anchor config
// must be verified against the CONFIGURED keys → rejected. This is the
// configured-root-of-trust proof: never trust the fetched anchor keys.
func TestResolveTrustChain_AnchorConfigForged(t *testing.T) {
	t.Parallel()
	realAnchor := newFedEntity(t, tcAnchorID)
	fakeAnchor := newFedEntity(t, tcAnchorID) // same id, different key
	leaf := newFedEntity(t, tcLeafID)

	f := newFakeFetcher()
	// The served anchor config is signed by the FAKE anchor key...
	f.configs[tcAnchorID] = fakeAnchor.entityConfig(t, nil, tcFetchURL, nil)
	f.configs[leaf.id] = leaf.entityConfig(t, []string{tcAnchorID}, "", nil)
	// ...and the fake anchor vouches for the leaf (so the only failure is the
	// anchor-config-vs-configured-keys check).
	f.subs[subKey(tcFetchURL, tcAnchorID, leaf.id)] = fakeAnchor.subordinateStatement(t, leaf, nil)

	// The resolver is configured with the REAL anchor's keys.
	r := resolverFor(t, f, realAnchor)
	_, err := r.ResolveTrustChain(context.Background(), leaf.id)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("forged anchor config: err = %v, want ErrTrustChainInvalid", err)
	}
}

// TestResolveTrustChain_IntermediateKeyNotVouchedByAnchor: the intermediate
// signs its Subordinate Statement about the leaf (SS_1) with a key the ANCHOR
// did NOT vouch for it (a key only in the intermediate's own self-config, not in
// the anchor's SS_2 about the intermediate). The canonical key-provenance rule
// verifies SS_1 against the ANCHOR-VOUCHED intermediate keys (SS_2.jwks), so an
// intermediate cannot smuggle in a self-asserted signing key the anchor never
// blessed → rejected. (This is the precise weakness of trusting an
// intermediate's self-config jwks instead of the vouched keys.)
func TestResolveTrustChain_IntermediateKeyNotVouchedByAnchor(t *testing.T) {
	t.Parallel()
	anchor := newFedEntity(t, tcAnchorID)
	interReal := newFedEntity(t, tcInterID)  // key A — what the anchor vouches
	interRogue := newFedEntity(t, tcInterID) // key B — same id, signs SS_1
	leaf := newFedEntity(t, tcLeafID)

	f := newFakeFetcher()
	f.configs[anchor.id] = anchor.entityConfig(t, nil, tcFetchURL, nil)
	// The intermediate's published config + authority_hints (navigation only).
	f.configs[interReal.id] = interReal.entityConfig(t, []string{anchor.id}, tcInterFch, nil)
	f.configs[leaf.id] = leaf.entityConfig(t, []string{interReal.id}, "", map[string]any{"client_name": "X"})
	// Anchor vouches the REAL intermediate keys (key A) in SS_2.
	f.subs[subKey(tcFetchURL, anchor.id, interReal.id)] = anchor.subordinateStatement(t, interReal, nil)
	// SS_1 (about the leaf) is signed by the ROGUE intermediate key (key B), which
	// the anchor never vouched. It still vouches the leaf's real keys.
	f.subs[subKey(tcInterFch, interReal.id, leaf.id)] = interRogue.subordinateStatement(t, leaf, nil)

	r := resolverFor(t, f, anchor)
	_, err := r.ResolveTrustChain(context.Background(), leaf.id)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("intermediate key not vouched by anchor: err = %v, want ErrTrustChainInvalid", err)
	}
}

// TestResolveTrustChain_SelfSignedLeafClaimingOwnAnchor: a self-signed leaf with
// NO authority_hints that is NOT a configured anchor → never anchors → rejected.
func TestResolveTrustChain_SelfSignedLeafClaimingOwnAnchor(t *testing.T) {
	t.Parallel()
	anchor := newFedEntity(t, tcAnchorID) // configured, but unrelated to the leaf
	leaf := newFedEntity(t, tcLeafID)
	f := newFakeFetcher()
	f.configs[anchor.id] = anchor.entityConfig(t, nil, tcFetchURL, nil)
	// Leaf is self-signed, no hints, claims to be its own root.
	f.configs[leaf.id] = leaf.entityConfig(t, nil, "", map[string]any{"client_name": "Rogue"})

	r := resolverFor(t, f, anchor)
	_, err := r.ResolveTrustChain(context.Background(), leaf.id)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("self-anchored non-configured leaf: err = %v, want ErrTrustChainInvalid", err)
	}
}

// TestResolveTrustChain_ChainNeverReachesConfiguredAnchor: a complete, validly-
// signed chain to a DIFFERENT (non-configured) anchor → rejected.
func TestResolveTrustChain_ChainNeverReachesConfiguredAnchor(t *testing.T) {
	t.Parallel()
	configuredAnchor := newFedEntity(t, "https://real-anchor.test")
	rogueAnchor := newFedEntity(t, "https://rogue-anchor.test")
	leaf := newFedEntity(t, tcLeafID)

	f := newFakeFetcher()
	f.configs[rogueAnchor.id] = rogueAnchor.entityConfig(t, nil, tcFetchURL, nil)
	f.configs[leaf.id] = leaf.entityConfig(t, []string{rogueAnchor.id}, "", nil)
	f.subs[subKey(tcFetchURL, rogueAnchor.id, leaf.id)] = rogueAnchor.subordinateStatement(t, leaf, nil)

	// Resolver trusts a DIFFERENT anchor.
	r := resolverFor(t, f, configuredAnchor)
	_, err := r.ResolveTrustChain(context.Background(), leaf.id)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("chain to rogue anchor: err = %v, want ErrTrustChainInvalid", err)
	}
}

// TestResolveTrustChain_TamperedSubordinateSignature: flip a byte in the
// intermediate's Subordinate Statement signature → rejected.
func TestResolveTrustChain_TamperedSubordinateSignature(t *testing.T) {
	t.Parallel()
	f, anchor, _, leaf := buildLinearFederation(t, map[string]any{"client_name": "X"}, nil, nil)
	// Tamper the inter->leaf subordinate statement (corrupt its last char).
	k := subKey(tcInterFch, tcInterID, tcLeafID)
	good := f.subs[k]
	f.subs[k] = good[:len(good)-2] + flipChar(good[len(good)-2:len(good)-1]) + good[len(good)-1:]

	r := resolverFor(t, f, anchor)
	_, err := r.ResolveTrustChain(context.Background(), leaf.id)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("tampered subordinate: err = %v, want ErrTrustChainInvalid", err)
	}
}

func flipChar(s string) string {
	if s == "A" {
		return "B"
	}
	return "A"
}

// ===========================================================================
// EXPIRY / iss-sub / typ (per-hop)
// ===========================================================================

// TestResolveTrustChain_ExpiredLeaf: leaf config expired well before the fixed
// clock → rejected (the date-bomb / clock-injection proof).
func TestResolveTrustChain_ExpiredLeaf(t *testing.T) {
	t.Parallel()
	anchor := newFedEntity(t, tcAnchorID)
	inter := newFedEntity(t, tcInterID)
	leaf := newFedEntity(t, tcLeafID)

	f := newFakeFetcher()
	f.configs[anchor.id] = anchor.entityConfig(t, nil, tcFetchURL, nil)
	f.configs[inter.id] = inter.entityConfig(t, []string{anchor.id}, tcInterFch, nil)
	// Leaf config: exp 2h before the fixed clock (> the 60s skew).
	expiredClaims := federation.EntityStatementClaims{
		Iss: leaf.id, Sub: leaf.id,
		Iat:            fedClock.Add(-3 * time.Hour).Unix(),
		Exp:            fedClock.Add(-2 * time.Hour).Unix(),
		JWKS:           federation.EntityJWKS{Keys: leaf.keys(t)},
		Metadata:       &federation.EntityMetadata{RP: map[string]any{"client_name": "Stale"}},
		AuthorityHints: []string{inter.id},
	}
	f.configs[leaf.id] = leaf.signStatement(t, expiredClaims)
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = anchor.subordinateStatement(t, inter, nil)
	f.subs[subKey(tcInterFch, inter.id, leaf.id)] = inter.subordinateStatement(t, leaf, nil)

	r := resolverFor(t, f, anchor)
	_, err := r.ResolveTrustChain(context.Background(), leaf.id)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("expired leaf: err = %v, want ErrTrustChainInvalid", err)
	}
}

// TestResolveTrustChain_ExpiredSubordinate: the anchor->inter subordinate
// statement is expired → rejected.
func TestResolveTrustChain_ExpiredSubordinate(t *testing.T) {
	t.Parallel()
	anchor := newFedEntity(t, tcAnchorID)
	inter := newFedEntity(t, tcInterID)
	leaf := newFedEntity(t, tcLeafID)

	f := newFakeFetcher()
	f.configs[anchor.id] = anchor.entityConfig(t, nil, tcFetchURL, nil)
	f.configs[inter.id] = inter.entityConfig(t, []string{anchor.id}, tcInterFch, nil)
	f.configs[leaf.id] = leaf.entityConfig(t, []string{inter.id}, "", nil)
	expiredSub := federation.EntityStatementClaims{
		Iss: anchor.id, Sub: inter.id,
		Iat:  fedClock.Add(-3 * time.Hour).Unix(),
		Exp:  fedClock.Add(-2 * time.Hour).Unix(),
		JWKS: federation.EntityJWKS{Keys: inter.keys(t)},
	}
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = anchor.signStatement(t, expiredSub)
	f.subs[subKey(tcInterFch, inter.id, leaf.id)] = inter.subordinateStatement(t, leaf, nil)

	r := resolverFor(t, f, anchor)
	_, err := r.ResolveTrustChain(context.Background(), leaf.id)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("expired subordinate: err = %v, want ErrTrustChainInvalid", err)
	}
}

// TestResolveTrustChain_NotYetValidLeaf: leaf iat far in the FUTURE (> skew) →
// rejected.
func TestResolveTrustChain_NotYetValidLeaf(t *testing.T) {
	t.Parallel()
	anchor := newFedEntity(t, tcAnchorID)
	inter := newFedEntity(t, tcInterID)
	leaf := newFedEntity(t, tcLeafID)

	f := newFakeFetcher()
	f.configs[anchor.id] = anchor.entityConfig(t, nil, tcFetchURL, nil)
	f.configs[inter.id] = inter.entityConfig(t, []string{anchor.id}, tcInterFch, nil)
	futureClaims := federation.EntityStatementClaims{
		Iss: leaf.id, Sub: leaf.id,
		Iat:            fedClock.Add(2 * time.Hour).Unix(),
		Exp:            fedClock.Add(4 * time.Hour).Unix(),
		JWKS:           federation.EntityJWKS{Keys: leaf.keys(t)},
		Metadata:       &federation.EntityMetadata{RP: map[string]any{"client_name": "Future"}},
		AuthorityHints: []string{inter.id},
	}
	f.configs[leaf.id] = leaf.signStatement(t, futureClaims)
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = anchor.subordinateStatement(t, inter, nil)
	f.subs[subKey(tcInterFch, inter.id, leaf.id)] = inter.subordinateStatement(t, leaf, nil)

	r := resolverFor(t, f, anchor)
	_, err := r.ResolveTrustChain(context.Background(), leaf.id)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("not-yet-valid leaf: err = %v, want ErrTrustChainInvalid", err)
	}
}

// TestResolveTrustChain_SubordinateIssMismatch: the anchor->inter subordinate
// statement has the WRONG iss (not the anchor) → rejected.
func TestResolveTrustChain_SubordinateIssMismatch(t *testing.T) {
	t.Parallel()
	anchor := newFedEntity(t, tcAnchorID)
	inter := newFedEntity(t, tcInterID)
	leaf := newFedEntity(t, tcLeafID)

	f := newFakeFetcher()
	f.configs[anchor.id] = anchor.entityConfig(t, nil, tcFetchURL, nil)
	f.configs[inter.id] = inter.entityConfig(t, []string{anchor.id}, tcInterFch, nil)
	f.configs[leaf.id] = leaf.entityConfig(t, []string{inter.id}, "", nil)
	// Subordinate statement signed by the anchor but with iss = some other id.
	badIss := federation.EntityStatementClaims{
		Iss: "https://imposter.test", Sub: inter.id,
		Iat:  fedClock.Unix(),
		Exp:  fedClock.Add(time.Hour).Unix(),
		JWKS: federation.EntityJWKS{Keys: inter.keys(t)},
	}
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = anchor.signStatement(t, badIss)
	f.subs[subKey(tcInterFch, inter.id, leaf.id)] = inter.subordinateStatement(t, leaf, nil)

	r := resolverFor(t, f, anchor)
	_, err := r.ResolveTrustChain(context.Background(), leaf.id)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("iss mismatch: err = %v, want ErrTrustChainInvalid", err)
	}
}

// TestResolveTrustChain_WrongTyp: a statement signed with the wrong JOSE typ
// (an access-token-shaped typ) is rejected by the typ gate.
func TestResolveTrustChain_WrongTyp(t *testing.T) {
	t.Parallel()
	anchor := newFedEntity(t, tcAnchorID)
	leaf := newFedEntity(t, tcLeafID)
	f := newFakeFetcher()
	// Anchor config signed with typ at+jwt instead of entity-statement+jwt.
	wrongTypAnchorClaims := federation.EntityStatementClaims{
		Iss: anchor.id, Sub: anchor.id,
		Iat:      fedClock.Unix(),
		Exp:      fedClock.Add(24 * time.Hour).Unix(),
		JWKS:     federation.EntityJWKS{Keys: anchor.keys(t)},
		Metadata: &federation.EntityMetadata{FederationEntity: &federation.FederationEntityMeta{FederationFetchEndpoint: tcFetchURL}},
	}
	wrongTyp, err := anchor.iss.SignJWT(context.Background(), "at+jwt", wrongTypAnchorClaims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	f.configs[anchor.id] = wrongTyp
	f.configs[leaf.id] = leaf.entityConfig(t, []string{anchor.id}, "", nil)
	f.subs[subKey(tcFetchURL, anchor.id, leaf.id)] = anchor.subordinateStatement(t, leaf, nil)

	r := resolverFor(t, f, anchor)
	_, err = r.ResolveTrustChain(context.Background(), leaf.id)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("wrong typ: err = %v, want ErrTrustChainInvalid", err)
	}
}

// ===========================================================================
// CYCLE / PATH-LENGTH BOUNDS (DoS guards)
// ===========================================================================

// TestResolveTrustChain_CyclicAuthorityHints: A hints B, B hints A (a cycle),
// neither a configured anchor → rejected, NO hang/stack-overflow.
func TestResolveTrustChain_CyclicAuthorityHints(t *testing.T) {
	t.Parallel()
	anchor := newFedEntity(t, tcAnchorID) // configured but unreachable
	a := newFedEntity(t, "https://a.cycle.test")
	b := newFedEntity(t, "https://b.cycle.test")
	leaf := newFedEntity(t, tcLeafID)

	f := newFakeFetcher()
	f.configs[anchor.id] = anchor.entityConfig(t, nil, tcFetchURL, nil)
	f.configs[a.id] = a.entityConfig(t, []string{b.id}, "https://a.cycle.test/fetch", nil)
	f.configs[b.id] = b.entityConfig(t, []string{a.id}, "https://b.cycle.test/fetch", nil)
	f.configs[leaf.id] = leaf.entityConfig(t, []string{a.id}, "", nil)
	// Subordinate statements forming the cycle.
	f.subs[subKey("https://a.cycle.test/fetch", a.id, leaf.id)] = a.subordinateStatement(t, leaf, nil)
	f.subs[subKey("https://b.cycle.test/fetch", b.id, a.id)] = b.subordinateStatement(t, a, nil)
	f.subs[subKey("https://a.cycle.test/fetch", a.id, b.id)] = a.subordinateStatement(t, b, nil)

	r := resolverFor(t, f, anchor)
	done := make(chan error, 1)
	go func() {
		_, err := r.ResolveTrustChain(context.Background(), leaf.id)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, federation.ErrTrustChainInvalid) {
			t.Fatalf("cyclic hints: err = %v, want ErrTrustChainInvalid", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ResolveTrustChain hung on a cyclic authority_hints")
	}
}

// TestResolveTrustChain_PathTooLong: a chain deeper than the configured bound →
// rejected.
func TestResolveTrustChain_PathTooLong(t *testing.T) {
	t.Parallel()
	anchor := newFedEntity(t, tcAnchorID)
	// Build a deep linear chain: leaf -> i1 -> i2 -> i3 -> anchor (3 inter hops).
	i1 := newFedEntity(t, "https://i1.test")
	i2 := newFedEntity(t, "https://i2.test")
	i3 := newFedEntity(t, "https://i3.test")
	leaf := newFedEntity(t, tcLeafID)

	f := newFakeFetcher()
	f.configs[anchor.id] = anchor.entityConfig(t, nil, "https://anchor.test/fetch", nil)
	f.configs[i3.id] = i3.entityConfig(t, []string{anchor.id}, "https://i3.test/fetch", nil)
	f.configs[i2.id] = i2.entityConfig(t, []string{i3.id}, "https://i2.test/fetch", nil)
	f.configs[i1.id] = i1.entityConfig(t, []string{i2.id}, "https://i1.test/fetch", nil)
	f.configs[leaf.id] = leaf.entityConfig(t, []string{i1.id}, "", nil)
	f.subs[subKey("https://anchor.test/fetch", anchor.id, i3.id)] = anchor.subordinateStatement(t, i3, nil)
	f.subs[subKey("https://i3.test/fetch", i3.id, i2.id)] = i3.subordinateStatement(t, i2, nil)
	f.subs[subKey("https://i2.test/fetch", i2.id, i1.id)] = i2.subordinateStatement(t, i1, nil)
	f.subs[subKey("https://i1.test/fetch", i1.id, leaf.id)] = i1.subordinateStatement(t, leaf, nil)

	// Bound the depth to 2 hops — the chain needs 4 → rejected.
	cfg := &federation.Config{
		TrustAnchors:       []federation.TrustAnchor{{EntityID: anchor.id, Keys: anchor.keys(t)}},
		MaxTrustChainDepth: 2,
	}
	r := federation.NewTrustChainResolver(cfg,
		federation.WithTrustChainFetcher(f),
		federation.WithTrustChainClock(func() time.Time { return fedClock }),
	)
	_, err := r.ResolveTrustChain(context.Background(), leaf.id)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("path too long: err = %v, want ErrTrustChainInvalid", err)
	}

	// With a sufficient bound (5, the default), the SAME chain resolves.
	r2 := resolverFor(t, f, anchor)
	if _, err := r2.ResolveTrustChain(context.Background(), leaf.id); err != nil {
		t.Fatalf("deep-but-within-bound chain should resolve: %v", err)
	}
}

// ===========================================================================
// FETCH FAILURE
// ===========================================================================

func TestResolveTrustChain_FetchError(t *testing.T) {
	t.Parallel()
	f, anchor, _, leaf := buildLinearFederation(t, map[string]any{"client_name": "X"}, nil, nil)
	f.fail[leaf.id] = errors.New("simulated transport failure")

	r := resolverFor(t, f, anchor)
	_, err := r.ResolveTrustChain(context.Background(), leaf.id)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("fetch error: err = %v, want ErrTrustChainInvalid", err)
	}
}

// TestResolveTrustChain_FanoutBudgetBounded: a wide branching federation where
// EVERY authority hint at every level is a dead end (none reaches the
// configured anchor) must (a) reject and (b) stay BOUNDED in total fetches (the
// fan-out DoS guard), not explode exponentially with depth × branching.
//
// Each node `n<path>` hints two children `n<path>l` and `n<path>r`, and each
// child publishes a Subordinate Statement ABOUT its parent (so the climb
// actually descends into the branch). The tree is `fanDepth` deep; none of the
// leaves is the configured anchor. A naive resolver fetches O(2^fanDepth)
// documents — the budget caps total fetches well below that.
func TestResolveTrustChain_FanoutBudgetBounded(t *testing.T) {
	t.Parallel()
	anchor := newFedEntity(t, tcAnchorID) // configured but never linked
	leaf := newFedEntity(t, tcLeafID)

	f := newFakeFetcher()
	f.configs[anchor.id] = anchor.entityConfig(t, nil, tcFetchURL, nil)

	const fanDepth = 7
	ents := map[string]*fedEntity{}
	idFor := func(path string) string { return "https://n" + path + ".fan.test" }
	fetchFor := func(path string) string { return idFor(path) + "/fetch" }

	// Create every node entity up front so a parent can mint the Subordinate
	// Statement about itself signed by... no: a Subordinate Statement about a
	// parent is issued BY the CHILD (the child is the superior in the hint
	// relationship). Build top-down: for node P with children C, C is P's
	// superior, so C issues "C about P".
	var build func(path string, depth int)
	build = func(path string, depth int) {
		id := idFor(path)
		ent := newFedEntity(t, id)
		ents[path] = ent
		var hints []string
		if depth < fanDepth {
			lp, rp := path+"l", path+"r"
			build(lp, depth+1)
			build(rp, depth+1)
			hints = []string{idFor(lp), idFor(rp)}
			// Each child (superior) issues a Subordinate Statement about THIS node.
			f.subs[subKey(fetchFor(lp), idFor(lp), id)] = ents[lp].subordinateStatement(t, ent, nil)
			f.subs[subKey(fetchFor(rp), idFor(rp), id)] = ents[rp].subordinateStatement(t, ent, nil)
		}
		f.configs[id] = ent.entityConfig(t, hints, fetchFor(path), nil)
	}
	build("", 0)

	rootID := idFor("")
	// Leaf hints the tree root; the root (superior) issues a subordinate
	// statement about the leaf so the first hop is taken, then the tree fans out
	// with no anchor anywhere.
	f.subs[subKey(fetchFor(""), rootID, leaf.id)] = ents[""].subordinateStatement(t, leaf, nil)
	f.configs[leaf.id] = leaf.entityConfig(t, []string{rootID}, "", nil)

	r := resolverFor(t, f, anchor)
	done := make(chan error, 1)
	go func() {
		_, err := r.ResolveTrustChain(context.Background(), leaf.id)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, federation.ErrTrustChainInvalid) {
			t.Fatalf("fan-out: err = %v, want ErrTrustChainInvalid", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ResolveTrustChain hung on a wide fan-out federation")
	}
	// The fetch count must stay far below the 2^7 = 128-node naive blow-up (which
	// at 2 fetches/node is ~256+ fetches). The budget for the default depth (5)
	// is (5+1)*16+2 = 98.
	if f.calls > maxFanoutBudgetCeiling {
		t.Fatalf("fan-out fetch count = %d, exceeds the budget ceiling (%d)", f.calls, maxFanoutBudgetCeiling)
	}
}

// maxFanoutBudgetCeiling mirrors maxTotalFetches(DefaultMaxTrustChainDepth) =
// (5+1)*16+2. Hard-coded here (the SDK helper is unexported) as the assertion
// ceiling for the fan-out DoS guard.
const maxFanoutBudgetCeiling = 98

// ===========================================================================
// DEFAULT-OFF (no configured anchors → inert)
// ===========================================================================

func TestResolveTrustChain_DisabledWhenNoAnchors(t *testing.T) {
	t.Parallel()
	r := federation.NewTrustChainResolver(&federation.Config{})
	if r.Enabled() {
		t.Fatal("resolver with no anchors must be disabled")
	}
	_, err := r.ResolveTrustChain(context.Background(), tcLeafID)
	if !errors.Is(err, federation.ErrFederationResolverDisabled) {
		t.Fatalf("disabled resolver: err = %v, want ErrFederationResolverDisabled", err)
	}

	// nil config is also disabled.
	rNil := federation.NewTrustChainResolver(nil)
	if rNil.Enabled() {
		t.Fatal("nil-config resolver must be disabled")
	}
	if _, err := rNil.ResolveTrustChain(context.Background(), tcLeafID); !errors.Is(err, federation.ErrFederationResolverDisabled) {
		t.Fatalf("nil-config resolver: err = %v, want ErrFederationResolverDisabled", err)
	}
}
