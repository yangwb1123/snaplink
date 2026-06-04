package federation_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/federation"
)

// ===========================================================================
// SLICE 3 — automatic client registration from a validated trust chain.
//
// Reuses the slice-2 FAKE federation harness (fedEntity / fakeFetcher /
// buildLinearFederation / resolverFor in trust_chain_test.go): a real Ed25519
// federation, a fixed clock, no network. These tests prove the
// RegistrationClientStore decorator: a VALIDATED federation RP becomes a usable
// client on a ClientStore miss; an INVALID chain stays unknown (oracle-safe);
// the metadata_policy constrains the derived client; the cache is entity-ID
// keyed + chain-exp bounded; default-off is a transparent pass-through.
// ===========================================================================

// countingClientStore is a real in-memory ClientStore (NO mock — wraps the
// shipped MemoryClientStore) that counts Get calls + reports the wrapped-store
// miss error, so a test can assert the federation fallback fires only on a miss
// and the wrapped hit short-circuits.
type countingClientStore struct {
	*defaultimpl.MemoryClientStore
	gets atomic.Int64
}

func newCountingClientStore() *countingClientStore {
	return &countingClientStore{MemoryClientStore: defaultimpl.NewMemoryClientStore()}
}

func (c *countingClientStore) Get(ctx context.Context, id string) (*core.Client, error) {
	c.gets.Add(1)
	return c.MemoryClientStore.Get(ctx, id)
}

// rpWithKeys returns leaf RP metadata carrying the entity's own published keys
// inline as the openid_relying_party `jwks` member (so the derived client can
// authenticate via private_key_jwt). The shape mirrors what the policy engine
// returns for an inline JWK Set: {"keys": []any{ map per key }}.
func rpWithKeys(t *testing.T, leaf *fedEntity, redirectURIs ...string) map[string]any {
	t.Helper()
	uris := make([]any, len(redirectURIs))
	for i, u := range redirectURIs {
		uris[i] = u
	}
	keys := leaf.keys(t)
	keyMaps := make([]any, len(keys))
	for i, k := range keys {
		keyMaps[i] = map[string]any{
			"kty": k.Kty,
			"crv": k.Crv,
			"x":   k.X,
			"kid": k.Kid,
		}
	}
	return map[string]any{
		"client_name":   "Federated RP",
		"redirect_uris": uris,
		"scope":         "openid profile",
		"jwks":          map[string]any{"keys": keyMaps},
	}
}

// regStore builds a RegistrationClientStore over a real inner store + the
// slice-2 resolver wired to the fake federation, sharing the fixed clock.
func regStore(t *testing.T, inner core.ClientStore, fetcher federation.EntityStatementFetcher, anchor *fedEntity, opts ...federation.RegistrationOption) *federation.RegistrationClientStore {
	t.Helper()
	resolver := resolverFor(t, fetcher, anchor)
	base := []federation.RegistrationOption{
		federation.WithRegistrationClock(func() time.Time { return fedClock }),
	}
	return federation.NewRegistrationClientStore(inner, resolver, append(base, opts...)...)
}

// ---------------------------------------------------------------------------
// VALID chain → admitted as a usable client.
// ---------------------------------------------------------------------------

func TestRegistration_ValidChain_DerivesUsableClient(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	f, anchor, _, _ := buildLinearFederationWithLeaf(t, leaf,
		rpWithKeys(t, leaf, "https://rp.federation.test/cb"), nil, nil)

	inner := newCountingClientStore()
	store := regStore(t, inner, f, anchor)

	client, err := store.Get(context.Background(), leaf.id)
	if err != nil {
		t.Fatalf("Get(federation RP) = %v, want a derived client", err)
	}
	if client.ID != leaf.id {
		t.Errorf("derived Client.ID = %q, want the entity id %q", client.ID, leaf.id)
	}
	if !client.Federation {
		t.Error("derived client must be marked Federation=true")
	}
	if client.Secret != "" {
		t.Error("federation client must carry NO secret (asymmetric auth only)")
	}
	if len(client.RedirectURIs) != 1 || client.RedirectURIs[0] != "https://rp.federation.test/cb" {
		t.Errorf("RedirectURIs = %v, want the policy-constrained redirect", client.RedirectURIs)
	}
	if len(client.JWKS) == 0 {
		t.Error("derived client must carry the chain-vouched JWKS for private_key_jwt")
	}
	if !client.Active {
		t.Error("a validated federation client is active (validation IS the gate)")
	}
	if !client.IsRedirectURIValid("https://rp.federation.test/cb") {
		t.Error("the policy-permitted redirect_uri must pass exact-match")
	}
}

// ---------------------------------------------------------------------------
// Pre-registered client wins — no federation resolution attempted.
// ---------------------------------------------------------------------------

func TestRegistration_PreRegisteredClientWins(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	anchor := newFedEntity(t, tcAnchorID)

	inner := newCountingClientStore()
	// Seed a DIFFERENT client under the SAME id the federation would resolve.
	inner.AddSeed(&core.Client{
		ID:           leaf.id,
		Secret:       "preexisting-secret",
		Active:       true,
		RedirectURIs: []string{"https://preregistered.example/cb"},
	})

	// A fetcher that FAILS every fetch — if federation were attempted the test
	// would surface it; the pre-registered hit must short-circuit before any
	// fetch.
	failing := newFakeFetcher()
	store := regStore(t, inner, failing, anchor)

	client, err := store.Get(context.Background(), leaf.id)
	if err != nil {
		t.Fatalf("Get(pre-registered) = %v, want the seeded client", err)
	}
	if client.Federation {
		t.Error("pre-registered client must NOT be a federation client")
	}
	if client.Secret != "preexisting-secret" {
		t.Errorf("got Client.Secret %q, want the pre-registered secret (store hit must win)", client.Secret)
	}
	if failing.calls != 0 {
		t.Errorf("federation fetcher was called %d times; a ClientStore HIT must short-circuit before any resolution", failing.calls)
	}
}

// ---------------------------------------------------------------------------
// INVALID chain → unknown client (oracle-safe, same as any unknown client_id).
// ---------------------------------------------------------------------------

func TestRegistration_InvalidChain_StaysUnknown(t *testing.T) {
	// A leaf whose chain NEVER reaches the configured anchor (no authority_hints
	// path to it) — slice-2 ResolveTrustChain fails closed.
	leaf := newFedEntity(t, tcLeafID)
	anchor := newFedEntity(t, tcAnchorID)
	rogue := newFedEntity(t, "https://rogue.federation.test")

	f := newFakeFetcher()
	// The configured anchor exists, but the leaf's only authority hint points
	// at a rogue (non-anchor) entity with no further hints → unanchored.
	f.configs[anchor.id] = anchor.entityConfig(t, nil, tcFetchURL, nil)
	f.configs[rogue.id] = rogue.entityConfig(t, nil, "https://rogue.federation.test/fetch", nil)
	f.configs[leaf.id] = leaf.entityConfig(t, []string{rogue.id}, "", rpWithKeys(t, leaf, "https://rp.federation.test/cb"))
	f.subs[subKey("https://rogue.federation.test/fetch", rogue.id, leaf.id)] = rogue.subordinateStatement(t, leaf, nil)

	inner := newCountingClientStore()
	store := regStore(t, inner, f, anchor)

	_, err := store.Get(context.Background(), leaf.id)
	if err == nil {
		t.Fatal("Get(unanchored RP) succeeded; an invalid chain must leave the client UNKNOWN")
	}
	// The wire-shape proof: the SAME unknown-client error as any unknown
	// client_id (the decorator returns the wrapped store's original miss).
	if !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(invalid chain) = %v, want ErrNoSuchClient (oracle-safe, byte-identical to any unknown client)", err)
	}
}

func TestRegistration_ForgedLeafKey_StaysUnknown(t *testing.T) {
	// The intermediate vouches for the leaf with DIFFERENT keys than the leaf
	// actually signed its config with → slice-2 leaf-signature check fails.
	anchor := newFedEntity(t, tcAnchorID)
	inter := newFedEntity(t, tcInterID)
	leaf := newFedEntity(t, tcLeafID)
	impostor := newFedEntity(t, tcLeafID) // same id, different keypair

	f := newFakeFetcher()
	f.configs[anchor.id] = anchor.entityConfig(t, nil, tcFetchURL, nil)
	f.configs[inter.id] = inter.entityConfig(t, []string{anchor.id}, tcInterFch, nil)
	// Leaf config is signed by the REAL leaf, but...
	f.configs[leaf.id] = leaf.entityConfig(t, []string{inter.id}, "", rpWithKeys(t, leaf, "https://rp.federation.test/cb"))
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = anchor.subordinateStatement(t, inter, nil)
	// ...the intermediate vouches for the IMPOSTOR's keys (a forged binding).
	f.subs[subKey(tcInterFch, inter.id, leaf.id)] = inter.subordinateStatement(t, impostor, nil)

	inner := newCountingClientStore()
	store := regStore(t, inner, f, anchor)

	_, err := store.Get(context.Background(), leaf.id)
	if !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(forged leaf key) = %v, want ErrNoSuchClient (no admission without a validated chain)", err)
	}
}

// ---------------------------------------------------------------------------
// metadata_policy CONSTRAINS the derived client.
// ---------------------------------------------------------------------------

func TestRegistration_PolicyConstrainsRedirectURIs(t *testing.T) {
	// The anchor's policy PINS redirect_uris to a single permitted value via
	// `value`. The leaf ASKS for two (one permitted, one rogue); the policy
	// pins the metadata to exactly the permitted one — the rogue is never on
	// the derived client.
	leaf := newFedEntity(t, tcLeafID)
	permitted := "https://rp.federation.test/cb"
	rogue := "https://attacker.example/steal"

	leafRP := rpWithKeys(t, leaf, permitted, rogue)
	anchorPolicy := map[string]map[string]map[string]any{
		"openid_relying_party": {
			"redirect_uris": {"value": []any{permitted}},
		},
	}
	f, anchor, _, leaf2 := buildLinearFederationWithLeaf(t, leaf, leafRP, anchorPolicy, nil)

	inner := newCountingClientStore()
	store := regStore(t, inner, f, anchor)

	client, err := store.Get(context.Background(), leaf2.id)
	if err != nil {
		t.Fatalf("Get = %v, want a derived client", err)
	}
	if client.IsRedirectURIValid(rogue) {
		t.Errorf("derived client accepts the rogue redirect_uri %q — the metadata_policy MUST bound it out", rogue)
	}
	if !client.IsRedirectURIValid(permitted) {
		t.Errorf("derived client rejects the policy-permitted redirect_uri %q", permitted)
	}
	if len(client.RedirectURIs) != 1 {
		t.Errorf("RedirectURIs = %v, want exactly the one policy-pinned value", client.RedirectURIs)
	}
}

func TestRegistration_PolicyConstrainsScope(t *testing.T) {
	// The anchor's policy caps scope to subset_of {openid}. The leaf asks for
	// "openid profile email"; the merged policy rejects the leaf metadata
	// (profile/email are not in the subset) → resolution fails → unknown.
	leaf := newFedEntity(t, tcLeafID)
	leafRP := rpWithKeys(t, leaf, "https://rp.federation.test/cb")
	leafRP["scope"] = "openid profile email"
	anchorPolicy := map[string]map[string]map[string]any{
		"openid_relying_party": {
			"scope": {"subset_of": []any{"openid"}},
		},
	}
	f, anchor, _, leaf2 := buildLinearFederationWithLeaf(t, leaf, leafRP, anchorPolicy, nil)

	inner := newCountingClientStore()
	store := regStore(t, inner, f, anchor)

	_, err := store.Get(context.Background(), leaf2.id)
	if !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(scope exceeds policy) = %v, want ErrNoSuchClient — an RP cannot exceed the federation scope policy", err)
	}
}

// ---------------------------------------------------------------------------
// Non-entity-ID unknown client → existing error, no resolution attempt.
// ---------------------------------------------------------------------------

func TestRegistration_NonEntityIDUnknown_NoResolutionAttempt(t *testing.T) {
	anchor := newFedEntity(t, tcAnchorID)
	f := newFakeFetcher()
	f.configs[anchor.id] = anchor.entityConfig(t, nil, tcFetchURL, nil)

	inner := newCountingClientStore()
	store := regStore(t, inner, f, anchor)

	for _, id := range []string{
		"plain-client-id",         // not a URL at all
		"http://insecure.test/rp", // http (not https)
		"ftp://weird.test/rp",     // wrong scheme
		"",                        // empty
	} {
		_, err := store.Get(context.Background(), id)
		if !errors.Is(err, core.ErrNoSuchClient) {
			t.Errorf("Get(%q) = %v, want ErrNoSuchClient (non-entity-id unknown)", id, err)
		}
	}
	// No fetch may have been attempted for any of these (they're not valid
	// HTTPS entity identifiers).
	if f.calls != 0 {
		t.Errorf("federation fetcher called %d times for non-entity-id client_ids; none should trigger resolution", f.calls)
	}
}

// ---------------------------------------------------------------------------
// Default-off: a nil/inert resolver makes the decorator a transparent
// pass-through (byte-identical to the wrapped store).
// ---------------------------------------------------------------------------

func TestRegistration_NilResolver_TransparentPassthrough(t *testing.T) {
	inner := newCountingClientStore()
	inner.AddSeed(&core.Client{ID: "c1", Active: true, Secret: "s"})

	// nil resolver ⇒ federation inert.
	store := federation.NewRegistrationClientStore(inner, nil)

	// Hit forwards.
	c, err := store.Get(context.Background(), "c1")
	if err != nil || c == nil || c.ID != "c1" {
		t.Fatalf("Get(c1) = (%v,%v), want the seeded client", c, err)
	}
	// Miss forwards the wrapped error unchanged, NO resolution.
	_, err = store.Get(context.Background(), "https://rp.federation.test")
	if !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(entity-id-shaped) with nil resolver = %v, want ErrNoSuchClient pass-through", err)
	}
}

func TestRegistration_DisabledResolver_NoAnchors_Passthrough(t *testing.T) {
	inner := newCountingClientStore()
	// A resolver built from a config with NO trust anchors is inert (Enabled()
	// == false) — the decorator must not attempt resolution.
	resolver := federation.NewTrustChainResolver(&federation.Config{},
		federation.WithTrustChainFetcher(newFakeFetcher()))
	store := federation.NewRegistrationClientStore(inner, resolver)

	_, err := store.Get(context.Background(), "https://rp.federation.test")
	if !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get with a no-anchor (inert) resolver = %v, want ErrNoSuchClient pass-through", err)
	}
}

// ---------------------------------------------------------------------------
// Cache: a second Get is served from cache within the chain exp; re-resolves
// after exp.
// ---------------------------------------------------------------------------

func TestRegistration_CachesWithinChainExp(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	f, anchor, _, leaf2 := buildLinearFederationWithLeaf(t, leaf,
		rpWithKeys(t, leaf, "https://rp.federation.test/cb"), nil, nil)

	inner := newCountingClientStore()
	store := regStore(t, inner, f, anchor)

	if _, err := store.Get(context.Background(), leaf2.id); err != nil {
		t.Fatalf("first Get: %v", err)
	}
	firstCalls := f.calls
	if firstCalls == 0 {
		t.Fatal("first Get made no fetches; expected a resolution")
	}
	// Second Get for the same RP, same (fixed) clock → cache hit, no new fetch.
	if _, err := store.Get(context.Background(), leaf2.id); err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if f.calls != firstCalls {
		t.Errorf("second Get made %d more fetches; a cached client within the chain exp must NOT re-resolve", f.calls-firstCalls)
	}
}

func TestRegistration_ReResolvesAfterChainExp(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	f, anchor, _, leaf2 := buildLinearFederationWithLeaf(t, leaf,
		rpWithKeys(t, leaf, "https://rp.federation.test/cb"), nil, nil)

	inner := newCountingClientStore()
	// A MOVING clock: starts at fedClock, then jumps PAST the chain exp
	// (fedClock + 24h) so the cached entry goes stale and the next Get
	// re-resolves. The resolver itself uses the fixed fedClock (resolverFor),
	// so the statements still validate; only the registration cache sees the
	// advanced time.
	var clk atomic.Int64
	clk.Store(fedClock.Unix())
	store := federation.NewRegistrationClientStore(inner, resolverFor(t, f, anchor),
		federation.WithRegistrationClock(func() time.Time { return time.Unix(clk.Load(), 0).UTC() }))

	if _, err := store.Get(context.Background(), leaf2.id); err != nil {
		t.Fatalf("first Get: %v", err)
	}
	firstCalls := f.calls

	// Advance the registration clock past the chain exp.
	clk.Store(fedClock.Add(25 * time.Hour).Unix())

	if _, err := store.Get(context.Background(), leaf2.id); err != nil {
		t.Fatalf("post-exp Get: %v", err)
	}
	if f.calls <= firstCalls {
		t.Errorf("post-exp Get made no new fetches (%d == %d); a stale chain MUST be re-resolved", f.calls, firstCalls)
	}
}

// ---------------------------------------------------------------------------
// Concurrency: a burst of concurrent first-time Gets for one RP resolves once
// and is race-free. (Run with -race.)
// ---------------------------------------------------------------------------

func TestRegistration_ConcurrentGets_RaceFree(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	f, anchor, _, leaf2 := buildLinearFederationWithLeaf(t, leaf,
		rpWithKeys(t, leaf, "https://rp.federation.test/cb"), nil, nil)

	inner := newCountingClientStore()
	store := regStore(t, inner, f, anchor)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := store.Get(context.Background(), leaf2.id)
			if err != nil || c == nil || c.ID != leaf2.id {
				t.Errorf("concurrent Get = (%v,%v), want the derived client", c, err)
			}
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// MetadataToClient unit edges.
// ---------------------------------------------------------------------------

func TestMetadataToClient_RequiresRedirectURI(t *testing.T) {
	_, err := federation.MetadataToClient("https://rp.test", map[string]any{
		"client_name": "No Redirect",
	}, nil, "")
	if !errors.Is(err, federation.ErrFederationMetadataInvalid) {
		t.Errorf("MetadataToClient(no redirect_uris) = %v, want ErrFederationMetadataInvalid", err)
	}
}

func TestMetadataToClient_PublicClientGetsPKCE(t *testing.T) {
	c, err := federation.MetadataToClient("https://rp.test", map[string]any{
		"redirect_uris":              []any{"https://rp.test/cb"},
		"token_endpoint_auth_method": "none",
	}, nil, "tenant-a")
	if err != nil {
		t.Fatalf("MetadataToClient: %v", err)
	}
	if !c.RequirePKCE {
		t.Error("a public (auth_method=none) federation client must RequirePKCE")
	}
	if c.TenantID != "tenant-a" {
		t.Errorf("TenantID = %q, want the stamped tenant", c.TenantID)
	}
	if c.Secret != "" {
		t.Error("federation client must have no secret")
	}
}

// ---------------------------------------------------------------------------
// Test helpers that extend the slice-2 harness with a caller-supplied leaf.
// ---------------------------------------------------------------------------

// buildLinearFederationWithLeaf is buildLinearFederation but for a CALLER-built
// leaf (so the leaf's keys can be threaded into its own RP `jwks` metadata
// before the topology is assembled). Returns the fetcher + anchor + intermediate
// + the (passed-through) leaf.
func buildLinearFederationWithLeaf(t *testing.T, leaf *fedEntity, leafRP map[string]any, anchorPolicy, interPolicy map[string]map[string]map[string]any) (*fakeFetcher, *fedEntity, *fedEntity, *fedEntity) {
	t.Helper()
	anchor := newFedEntity(t, tcAnchorID)
	inter := newFedEntity(t, tcInterID)

	f := newFakeFetcher()
	f.configs[anchor.id] = anchor.entityConfig(t, nil, tcFetchURL, nil)
	f.configs[inter.id] = inter.entityConfig(t, []string{anchor.id}, tcInterFch, nil)
	f.configs[leaf.id] = leaf.entityConfig(t, []string{inter.id}, "", leafRP)
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = anchor.subordinateStatement(t, inter, anchorPolicy)
	f.subs[subKey(tcInterFch, inter.id, leaf.id)] = inter.subordinateStatement(t, leaf, interPolicy)
	return f, anchor, inter, leaf
}
