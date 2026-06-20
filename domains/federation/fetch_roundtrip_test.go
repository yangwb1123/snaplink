package federation_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/federation"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/shared/core"
)

// THE STRONGEST PROOF: the OP-as-intermediate round-trip. Slice 2's
// ResolveTrustChain CONSUMES exactly what the §8 Federation Fetch endpoint
// ISSUES. The topology: a leaf RP lists THIS server (the intermediate) in its
// authority_hints; THIS server's /fetch issues the Subordinate Statement about
// the leaf; a higher anchor vouches for THIS server. The resolver climbs
// leaf -> this-server -> anchor and the chain validates end-to-end — proving
// the Subordinate Statement this server authors is a spec-correct chain link.
//
// The crux: the intermediate's federation_fetch_endpoint is served by the REAL
// federation.HandleFederationFetch handler (not a pre-baked statement), driven
// over an httptest recorder. So slice 2 validates the genuine §8 output.

const (
	rtAnchorID = "https://anchor.rt.federation.test"
	rtInterID  = "https://intermediate.rt.federation.test" // THIS server (the OP as intermediate)
	rtLeafID   = "https://rp.rt.federation.test"
	rtAnchorFx = "https://anchor.rt.federation.test/fetch"
	rtInterFx  = "https://intermediate.rt.federation.test/fetch"
)

// opIntermediateFetcher serves the intermediate's federation_fetch_endpoint by
// invoking the REAL §8 handler (federation.HandleFederationFetch) over a
// recorder, and delegates every other fetch to an inner fakeFetcher. This is
// what makes the test a genuine round-trip: the intermediate->leaf Subordinate
// Statement is produced by the production §8 code path, not hand-built.
type opIntermediateFetcher struct {
	inner     *fakeFetcher
	interDeps federation.FetchDeps // drives HandleFederationFetch for the intermediate
}

func (f *opIntermediateFetcher) FetchEntityConfiguration(ctx context.Context, entityID string) ([]byte, error) {
	return f.inner.FetchEntityConfiguration(ctx, entityID)
}

func (f *opIntermediateFetcher) FetchSubordinateStatement(ctx context.Context, endpoint, issuer, subject string) ([]byte, error) {
	// When the resolver asks the INTERMEDIATE's fetch endpoint for a statement
	// about the leaf, serve it through the REAL §8 handler (iss = intermediate,
	// sub = the requested subject). Every other subordinate fetch (the anchor's
	// statement about the intermediate) is the inner fake's pre-built one.
	if endpoint == rtInterFx && issuer == rtInterID {
		q := url.Values{}
		q.Set("sub", subject)
		q.Set("iss", issuer)
		req := httptest.NewRequest(http.MethodGet, core.PathFederationFetch+"?"+q.Encode(), nil)
		rec := httptest.NewRecorder()
		hctx := core.NewContext(rec, req)
		federation.HandleFederationFetch(f.interDeps, hctx)
		if rec.Code != http.StatusOK {
			return nil, &fetchHTTPError{status: rec.Code, body: rec.Body.String()}
		}
		return rec.Body.Bytes(), nil
	}
	return f.inner.FetchSubordinateStatement(ctx, endpoint, issuer, subject)
}

type fetchHTTPError struct {
	status int
	body   string
}

func (e *fetchHTTPError) Error() string { return "fetch failed: " + e.body }

func TestFederationFetch_OPAsIntermediate_RoundTrip(t *testing.T) {
	clock := time.Unix(1_900_000_000, 0).UTC()

	// Three entities, each its own keypair.
	anchor := newFedEntity(t, rtAnchorID)
	inter := newFedEntity(t, rtInterID) // THIS server, acting as intermediate
	leaf := newFedEntity(t, rtLeafID)

	// The intermediate's §8 FetchDeps: it vouches for the LEAF's keys (operator
	// config) and signs Subordinate Statements with its OWN key. The clock is
	// the same fixed instant the resolver validates against (deterministic exp).
	leafKeys := leaf.keys(t)
	interDeps := &fetchDeps{
		iss: inter.iss,
		cfg: &federation.Config{
			Subordinates: []federation.SubordinateEntity{{
				EntityID: leaf.id,
				Keys:     leafKeys, // the keys this server vouches for the leaf
			}},
		},
		cache:  federation.NewSubordinateStatementCache(),
		now:    clock,
		issuer: inter.id,
	}

	// The fake federation. The intermediate's Entity Configuration advertises its
	// §8 fetch endpoint (so the resolver climbs through it). Its authority_hints
	// name the anchor. The leaf names the intermediate. The anchor vouches for
	// the intermediate (a pre-built SS); the intermediate->leaf SS is served LIVE
	// by the §8 handler via opIntermediateFetcher.
	inner := newFakeFetcher()
	inner.configs[anchor.id] = anchor.entityConfig(t, nil, rtAnchorFx, nil)
	inner.configs[inter.id] = inter.entityConfig(t, []string{anchor.id}, rtInterFx, nil)
	inner.configs[leaf.id] = leaf.entityConfig(t, []string{inter.id}, "", map[string]any{
		"client_name":   "Round-Trip RP",
		"redirect_uris": []any{"https://rp.rt.federation.test/cb"},
	})
	inner.subs[subKey(rtAnchorFx, anchor.id, inter.id)] = anchor.subordinateStatement(t, inter, nil)

	fetcher := &opIntermediateFetcher{inner: inner, interDeps: interDeps}

	// Resolver rooted in the anchor, wired to the round-trip fetcher + the fixed
	// clock.
	cfg := &federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: anchor.id, Keys: anchor.keys(t)}},
	}
	r := federation.NewTrustChainResolver(cfg,
		federation.WithTrustChainFetcher(fetcher),
		federation.WithTrustChainClock(func() time.Time { return clock }),
	)

	chain, err := r.ResolveTrustChain(context.Background(), leaf.id)
	if err != nil {
		t.Fatalf("ResolveTrustChain through the OP-as-intermediate failed: %v", err)
	}

	// End-to-end: the chain terminates at the configured anchor, starts at the
	// leaf, and the intermediate->leaf link (the §8 output) validated.
	if chain.LeafEntityID != leaf.id {
		t.Errorf("LeafEntityID = %q, want %q", chain.LeafEntityID, leaf.id)
	}
	if chain.AnchorEntityID != anchor.id {
		t.Errorf("AnchorEntityID = %q, want the configured anchor %q", chain.AnchorEntityID, anchor.id)
	}
	// Canonical chain: [leafConfig, SS(inter->leaf [§8 LIVE]), SS(anchor->inter),
	// anchorConfig] = 4.
	if len(chain.Statements) != 4 {
		t.Fatalf("chain length = %d, want 4 (leaf, §8 SS, anchor SS, anchor config)", len(chain.Statements))
	}
	if chain.ResolvedRPMetadata["client_name"] != "Round-Trip RP" {
		t.Errorf("resolved RP client_name = %v, want Round-Trip RP", chain.ResolvedRPMetadata["client_name"])
	}
}

// TestFederationFetch_OPAsIntermediate_PolicyEnforced layers the §10 metadata
// policy onto the round-trip: the §8 endpoint AUTHORS a metadata_policy into the
// intermediate->leaf Subordinate Statement, and slice 2 ENFORCES it on the
// leaf's openid_relying_party metadata — proving the OP-side authoring and the
// consuming-side enforcement compose. Here the policy PINS client_name; the
// resolved metadata must reflect it.
func TestFederationFetch_OPAsIntermediate_PolicyEnforced(t *testing.T) {
	clock := time.Unix(1_900_000_000, 0).UTC()

	anchor := newFedEntity(t, rtAnchorID)
	inter := newFedEntity(t, rtInterID)
	leaf := newFedEntity(t, rtLeafID)

	// The intermediate imposes a metadata_policy pinning client_name via the §8
	// statement it authors.
	policy := map[string]map[string]map[string]any{
		"openid_relying_party": {
			"client_name": {"value": "Policy-Pinned"},
		},
	}
	interDeps := &fetchDeps{
		iss: inter.iss,
		cfg: &federation.Config{
			Subordinates: []federation.SubordinateEntity{{
				EntityID:       leaf.id,
				Keys:           leaf.keys(t),
				MetadataPolicy: policy,
			}},
		},
		cache:  federation.NewSubordinateStatementCache(),
		now:    clock,
		issuer: inter.id,
	}

	inner := newFakeFetcher()
	inner.configs[anchor.id] = anchor.entityConfig(t, nil, rtAnchorFx, nil)
	inner.configs[inter.id] = inter.entityConfig(t, []string{anchor.id}, rtInterFx, nil)
	// The leaf SELF-ASSERTS a different client_name; the pinned policy overrides.
	inner.configs[leaf.id] = leaf.entityConfig(t, []string{inter.id}, "", map[string]any{
		"client_name": "Leaf-Asserted",
	})
	inner.subs[subKey(rtAnchorFx, anchor.id, inter.id)] = anchor.subordinateStatement(t, inter, nil)

	fetcher := &opIntermediateFetcher{inner: inner, interDeps: interDeps}
	cfg := &federation.Config{TrustAnchors: []federation.TrustAnchor{{EntityID: anchor.id, Keys: anchor.keys(t)}}}
	r := federation.NewTrustChainResolver(cfg,
		federation.WithTrustChainFetcher(fetcher),
		federation.WithTrustChainClock(func() time.Time { return clock }),
	)

	chain, err := r.ResolveTrustChain(context.Background(), leaf.id)
	if err != nil {
		t.Fatalf("ResolveTrustChain: %v", err)
	}
	// The §8-authored policy was enforced: the pinned value wins over the leaf's
	// self-asserted one.
	if got := chain.ResolvedRPMetadata["client_name"]; got != "Policy-Pinned" {
		t.Errorf("resolved client_name = %v, want Policy-Pinned (the §8-authored metadata_policy must override the leaf's self-asserted value)", got)
	}
}

// sanity: the round-trip fetchDeps shape matches the production accessor seam.
var _ federation.FetchDeps = (*fetchDeps)(nil)

// keep defaultimpl imported (used by newFedEntity in trust_chain_test.go is in
// the same package; this guards against an unused-import drift if the helper
// moves).
var _ = defaultimpl.NewEd25519JWTIssuer
