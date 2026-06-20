package federation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/federation"
	"github.com/snaplink/sso/shared/core"
)

// ===========================================================================
// SLICE 4c — OpenID Federation 1.0 §3.1.2/§7 FEDERATION-RESOLVED trust-mark
// issuers (the DYNAMIC-FEDERATION model). Opt-in
// (AllowFederationResolvedTrustMarkIssuers, default-OFF byte-identical): when a
// required mark's iss is NOT operator-pre-configured, the issuer is discovered
// as a federation entity (ResolveTrustChain to a CONFIGURED anchor) and MUST be
// listed in that ANCHOR's validated trust_mark_issuers for the required type;
// only then do the issuer's chain-validated keys verify the mark, under the SAME
// slice-4b checks (sub==RP, signed-type authoritative, typ, freshness).
//
// Reuses the slice-2/3/4b FAKE federation harness (fedEntity / fakeFetcher /
// signTrustMark / leafConfigWithTrustMarks / fedClock): a real Ed25519
// federation, real issuer-signed marks, a fixed clock, no network. The crux
// proofs: an anchor-authorized resolved issuer ADMITS; an issuer that chains but
// is NOT anchor-authorized (or authorized for a DIFFERENT type) is REJECTED; an
// issuer that does NOT chain to a configured anchor is REJECTED; the slice-4b
// invariants still apply on the resolved path; and the default-off + configured
// paths are unchanged.
// ===========================================================================

const (
	// tmrIssuerID is a Trust Mark Issuer that is ITSELF a federation entity
	// (resolved via its chain), distinct from the slice-4b operator-configured
	// issuer ids so the two paths never collide.
	tmrIssuerID = "https://fed-resolved-issuer.federation.test"
	// tmrIssuerOtherID is a DIFFERENT issuer the anchor may authorize instead, to
	// prove "chains but not anchor-authorized for THIS issuer" rejects.
	tmrIssuerOtherID = "https://fed-resolved-issuer-2.federation.test"
)

// anchorConfigWithTMI builds + signs an anchor Entity Configuration carrying the
// §3.1.2 trust_mark_issuers claim (in metadata.federation_entity) in addition to
// the federation_fetch_endpoint. This is what authorizes a federation-resolved
// issuer: the map lives on the ANCHOR (the root of trust), not the issuer.
func anchorConfigWithTMI(t *testing.T, anchor *fedEntity, fetchEndpoint string, trustMarkIssuers map[string][]string) string {
	t.Helper()
	claims := federation.EntityStatementClaims{
		Iss:  anchor.id,
		Sub:  anchor.id,
		Iat:  fedClock.Unix(),
		Exp:  fedClock.Add(24 * time.Hour).Unix(),
		JWKS: federation.EntityJWKS{Keys: anchor.keys(t)},
		Metadata: &federation.EntityMetadata{
			FederationEntity: &federation.FederationEntityMeta{
				FederationFetchEndpoint: fetchEndpoint,
				TrustMarkIssuers:        trustMarkIssuers,
			},
		},
	}
	return anchor.signStatement(t, claims)
}

// fedResolvedConfig is the federation Config for the slice-4c gate: the required
// types, the (possibly empty) operator-configured issuers, and the OPT-IN flag
// turned ON. maxClockSkew is left at the SDK default.
func fedResolvedConfig(requiredTypes []string, issuers ...federation.TrustMarkIssuer) *federation.Config {
	return &federation.Config{
		RequiredTrustMarkTypes:                  requiredTypes,
		TrustMarkIssuers:                        issuers,
		AllowFederationResolvedTrustMarkIssuers: true,
	}
}

// buildResolvedIssuerFederation wires a fake federation where BOTH the leaf RP
// and the Trust Mark ISSUER are members chaining to the SAME configured anchor:
//
//	anchor (carries trust_mark_issuers) --sub--> issuer    (direct child)
//	anchor --sub--> intermediate --sub--> leaf RP (carries the issuer-signed mark)
//
// markType is the SIGNED type of the mark the leaf carries; anchorTMI is the
// anchor's trust_mark_issuers map (the authorization root). Returns the fetcher
// + the anchor + the issuer entity.
func buildResolvedIssuerFederation(t *testing.T, leaf, issuer *fedEntity, markType string, markIat, markExp int64, markSub string, anchorTMI map[string][]string) (*fakeFetcher, *fedEntity) {
	t.Helper()
	anchor := newFedEntity(t, tcAnchorID)
	inter := newFedEntity(t, tcInterID)

	// The leaf RP's mark, signed by the issuer's key (sub defaults to the leaf).
	if markSub == "" {
		markSub = leaf.id
	}
	mark := signTrustMark(t, issuer, markSub, markType, markIat, markExp)

	f := newFakeFetcher()
	// Anchor config carries trust_mark_issuers (the authorization root) + the
	// fetch endpoint so it can vouch for its subordinates.
	f.configs[anchor.id] = anchorConfigWithTMI(t, anchor, tcFetchURL, anchorTMI)
	// Intermediate + leaf (the RP) — the slice-3 linear path.
	f.configs[inter.id] = inter.entityConfig(t, []string{anchor.id}, tcInterFch, nil)
	f.configs[leaf.id] = leafConfigWithTrustMarks(t, leaf, []string{inter.id},
		rpWithKeys(t, leaf, "https://rp.federation.test/cb"),
		[]federation.TrustMarkEntry{{TrustMarkType: markType, TrustMark: mark}})
	// The ISSUER as a federation entity — a DIRECT child of the anchor.
	f.configs[issuer.id] = issuer.entityConfig(t, []string{anchor.id}, "", nil)

	// Subordinate statements: anchor->inter, inter->leaf, anchor->issuer.
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = anchor.subordinateStatement(t, inter, nil)
	f.subs[subKey(tcInterFch, inter.id, leaf.id)] = inter.subordinateStatement(t, leaf, nil)
	f.subs[subKey(tcFetchURL, anchor.id, issuer.id)] = anchor.subordinateStatement(t, issuer, nil)
	return f, anchor
}

// ---------------------------------------------------------------------------
// FLAG ON: a federation-resolved issuer that CHAINS to the configured anchor
// AND is listed in that anchor's trust_mark_issuers for the type -> ADMITTED.
// ---------------------------------------------------------------------------

func TestTrustMarkResolved_AnchorAuthorizedIssuer_Admitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmrIssuerID)

	// The anchor authorizes THIS issuer for THIS type.
	anchorTMI := map[string][]string{tmType: {issuer.id}}
	f, anchor := buildResolvedIssuerFederation(t, leaf, issuer, tmType,
		fedClock.Unix(), fedClock.Add(24*time.Hour).Unix(), leaf.id, anchorTMI)

	// No operator-configured issuers at all — the ONLY way to satisfy is the
	// federation-resolved path (flag ON).
	store := tmStore(t, f, anchor, fedResolvedConfig([]string{tmType}))

	client, err := store.Get(context.Background(), leaf.id)
	if err != nil {
		t.Fatalf("Get(RP, anchor-authorized resolved issuer) = %v, want admitted", err)
	}
	if client == nil || client.ID != leaf.id || !client.Federation {
		t.Errorf("derived client = %+v, want the federation client for the RP", client)
	}
}

// The anchor's trust_mark_issuers array for the type is EMPTY -> per spec §3.1.2
// "anyone MAY issue" -> a chaining issuer is ADMITTED.
func TestTrustMarkResolved_AnchorEmptyArrayAuthorizesAnyone_Admitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmrIssuerID)

	// Empty array for the type = anyone authorized.
	anchorTMI := map[string][]string{tmType: {}}
	f, anchor := buildResolvedIssuerFederation(t, leaf, issuer, tmType,
		fedClock.Unix(), 0, leaf.id, anchorTMI)

	store := tmStore(t, f, anchor, fedResolvedConfig([]string{tmType}))

	if _, err := store.Get(context.Background(), leaf.id); err != nil {
		t.Fatalf("Get(empty trust_mark_issuers array = anyone) = %v, want admitted", err)
	}
}

// ---------------------------------------------------------------------------
// FLAG ON: an issuer that CHAINS to the anchor but is NOT listed in the
// anchor's trust_mark_issuers for the type -> REJECTED (the anchor is the
// authorization root; chaining alone is not enough).
// ---------------------------------------------------------------------------

func TestTrustMarkResolved_ChainsButNotAnchorAuthorized_NotAdmitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmrIssuerID)

	// The anchor authorizes a DIFFERENT entity (not this issuer) for the type.
	anchorTMI := map[string][]string{tmType: {tmrIssuerOtherID}}
	f, anchor := buildResolvedIssuerFederation(t, leaf, issuer, tmType,
		fedClock.Unix(), 0, leaf.id, anchorTMI)

	store := tmStore(t, f, anchor, fedResolvedConfig([]string{tmType}))

	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(issuer chains but not anchor-authorized) = %v, want ErrNoSuchClient (anchor is the authz root)", err)
	}
}

// The anchor publishes NO trust_mark_issuers at all -> an absent entry for the
// type authorizes NO one (fail-closed reading of the spec's unspecified case)
// -> REJECTED even though the issuer chains.
func TestTrustMarkResolved_AnchorHasNoTrustMarkIssuers_NotAdmitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmrIssuerID)

	// nil trust_mark_issuers on the anchor.
	f, anchor := buildResolvedIssuerFederation(t, leaf, issuer, tmType,
		fedClock.Unix(), 0, leaf.id, nil)

	store := tmStore(t, f, anchor, fedResolvedConfig([]string{tmType}))

	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(anchor has no trust_mark_issuers) = %v, want ErrNoSuchClient (absent entry authorizes no one)", err)
	}
}

// ---------------------------------------------------------------------------
// FLAG ON: an issuer that does NOT chain to any configured anchor (forged /
// standalone) -> REJECTED (not a federation member rooted in operator trust).
// ---------------------------------------------------------------------------

func TestTrustMarkResolved_IssuerNotChainingToAnchor_NotAdmitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmrIssuerID)

	// Build the standard federation but DO NOT make the issuer a member: it has no
	// subordinate statement from the anchor, and its config has no usable
	// authority_hints reaching the anchor. The leaf still carries the mark.
	anchor := newFedEntity(t, tcAnchorID)
	inter := newFedEntity(t, tcInterID)

	mark := signTrustMark(t, issuer, leaf.id, tmType, fedClock.Unix(), 0)

	f := newFakeFetcher()
	// Anchor would authorize the issuer IF it chained — proving the rejection is
	// purely the chain failure, not an authorization gap.
	f.configs[anchor.id] = anchorConfigWithTMI(t, anchor, tcFetchURL, map[string][]string{tmType: {issuer.id}})
	f.configs[inter.id] = inter.entityConfig(t, []string{anchor.id}, tcInterFch, nil)
	f.configs[leaf.id] = leafConfigWithTrustMarks(t, leaf, []string{inter.id},
		rpWithKeys(t, leaf, "https://rp.federation.test/cb"),
		[]federation.TrustMarkEntry{{TrustMarkType: tmType, TrustMark: mark}})
	// The issuer's config exists but is SELF-SIGNED with NO authority_hints and is
	// NOT a configured anchor -> it never chains to a trust anchor.
	f.configs[issuer.id] = issuer.entityConfig(t, nil, "", nil)
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = anchor.subordinateStatement(t, inter, nil)
	f.subs[subKey(tcInterFch, inter.id, leaf.id)] = inter.subordinateStatement(t, leaf, nil)
	// NO anchor->issuer subordinate statement: the issuer is not vouched.

	store := tmStore(t, f, anchor, fedResolvedConfig([]string{tmType}))

	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(issuer not chaining to a configured anchor) = %v, want ErrNoSuchClient (forged/standalone issuer rejected)", err)
	}
}

// A forged issuer chain: the issuer's config is signed by an impostor key the
// anchor never vouched -> the chain validation fails -> REJECTED.
func TestTrustMarkResolved_ForgedIssuerChain_NotAdmitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmrIssuerID)
	impostor := newFedEntity(t, tmrIssuerID) // same id, DIFFERENT key

	anchor := newFedEntity(t, tcAnchorID)
	inter := newFedEntity(t, tcInterID)

	// The mark is signed by the REAL issuer key (so the only defect is the chain).
	mark := signTrustMark(t, issuer, leaf.id, tmType, fedClock.Unix(), 0)

	f := newFakeFetcher()
	f.configs[anchor.id] = anchorConfigWithTMI(t, anchor, tcFetchURL, map[string][]string{tmType: {issuer.id}})
	f.configs[inter.id] = inter.entityConfig(t, []string{anchor.id}, tcInterFch, nil)
	f.configs[leaf.id] = leafConfigWithTrustMarks(t, leaf, []string{inter.id},
		rpWithKeys(t, leaf, "https://rp.federation.test/cb"),
		[]federation.TrustMarkEntry{{TrustMarkType: tmType, TrustMark: mark}})
	// The issuer's CONFIG is signed by the impostor key...
	f.configs[issuer.id] = impostor.entityConfig(t, []string{anchor.id}, "", nil)
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = anchor.subordinateStatement(t, inter, nil)
	f.subs[subKey(tcInterFch, inter.id, leaf.id)] = inter.subordinateStatement(t, leaf, nil)
	// ...but the anchor vouches the REAL issuer keys -> the issuer config sig fails.
	f.subs[subKey(tcFetchURL, anchor.id, issuer.id)] = anchor.subordinateStatement(t, issuer, nil)

	store := tmStore(t, f, anchor, fedResolvedConfig([]string{tmType}))

	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(forged issuer chain) = %v, want ErrNoSuchClient (chain validation fails)", err)
	}
}

// ---------------------------------------------------------------------------
// FLAG ON: per-type authorization. An issuer the anchor authorizes for type X
// presenting a mark of type Y -> REJECTED (the anchor authorizes per type).
// ---------------------------------------------------------------------------

func TestTrustMarkResolved_AuthorizedForOtherType_NotAdmitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmrIssuerID)

	// The anchor authorizes the issuer for tmTypeOther, but the required type (and
	// the mark's SIGNED type) is tmType -> not authorized for tmType.
	anchorTMI := map[string][]string{tmTypeOther: {issuer.id}}
	f, anchor := buildResolvedIssuerFederation(t, leaf, issuer, tmType,
		fedClock.Unix(), 0, leaf.id, anchorTMI)

	store := tmStore(t, f, anchor, fedResolvedConfig([]string{tmType}))

	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(issuer authorized for a different type) = %v, want ErrNoSuchClient (per-type authorization)", err)
	}
}

// ---------------------------------------------------------------------------
// FLAG ON: the slice-4b invariants STILL apply on the resolved path.
// ---------------------------------------------------------------------------

// Wrong subject (confused-deputy) on a resolved-issuer mark -> REJECTED.
func TestTrustMarkResolved_WrongSubject_NotAdmitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmrIssuerID)

	// A valid, anchor-authorized resolved issuer — but the mark's sub is a
	// DIFFERENT entity. The confused-deputy guard must still reject.
	anchorTMI := map[string][]string{tmType: {issuer.id}}
	f, anchor := buildResolvedIssuerFederation(t, leaf, issuer, tmType,
		fedClock.Unix(), 0, "https://some-other-rp.federation.test", anchorTMI)

	store := tmStore(t, f, anchor, fedResolvedConfig([]string{tmType}))

	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(resolved issuer, wrong subject) = %v, want ErrNoSuchClient (confused-deputy still closed)", err)
	}
}

// Expired resolved-issuer mark -> REJECTED (freshness still applies).
func TestTrustMarkResolved_ExpiredMark_NotAdmitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmrIssuerID)

	anchorTMI := map[string][]string{tmType: {issuer.id}}
	// exp 2h before the fixed clock (past the 60s skew).
	f, anchor := buildResolvedIssuerFederation(t, leaf, issuer, tmType,
		fedClock.Add(-3*time.Hour).Unix(), fedClock.Add(-2*time.Hour).Unix(), leaf.id, anchorTMI)

	store := tmStore(t, f, anchor, fedResolvedConfig([]string{tmType}))

	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(resolved issuer, expired mark) = %v, want ErrNoSuchClient (freshness still applies)", err)
	}
}

// Wrong SIGNED type on a resolved-issuer mark (wrapper claims the required type
// over a different signed type) -> REJECTED (signed type authoritative). The
// anchor authorizes the issuer broadly (for BOTH types) so the ONLY defect is
// the signed-type mismatch, not the authorization.
func TestTrustMarkResolved_WrongSignedType_NotAdmitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmrIssuerID)

	anchor := newFedEntity(t, tcAnchorID)
	inter := newFedEntity(t, tcInterID)

	// The mark's SIGNED type is tmTypeOther; the wrapper lies, claiming tmType.
	mark := signTrustMark(t, issuer, leaf.id, tmTypeOther, fedClock.Unix(), 0)

	f := newFakeFetcher()
	// Anchor authorizes the issuer for BOTH types (so an authorization gap is not
	// the reason for rejection — the signed-type mismatch is).
	f.configs[anchor.id] = anchorConfigWithTMI(t, anchor, tcFetchURL,
		map[string][]string{tmType: {issuer.id}, tmTypeOther: {issuer.id}})
	f.configs[inter.id] = inter.entityConfig(t, []string{anchor.id}, tcInterFch, nil)
	f.configs[leaf.id] = leafConfigWithTrustMarks(t, leaf, []string{inter.id},
		rpWithKeys(t, leaf, "https://rp.federation.test/cb"),
		[]federation.TrustMarkEntry{{TrustMarkType: tmType, TrustMark: mark}}) // wrapper says tmType
	f.configs[issuer.id] = issuer.entityConfig(t, []string{anchor.id}, "", nil)
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = anchor.subordinateStatement(t, inter, nil)
	f.subs[subKey(tcInterFch, inter.id, leaf.id)] = inter.subordinateStatement(t, leaf, nil)
	f.subs[subKey(tcFetchURL, anchor.id, issuer.id)] = anchor.subordinateStatement(t, issuer, nil)

	store := tmStore(t, f, anchor, fedResolvedConfig([]string{tmType}))

	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(resolved issuer, wrong signed type) = %v, want ErrNoSuchClient (signed type authoritative)", err)
	}
}

// A forged mark (signed by an impostor key, NOT the resolved issuer's chain-
// validated key) -> REJECTED. The issuer chains + is anchor-authorized, but the
// mark's signature doesn't verify against the issuer's chain-vouched keys.
func TestTrustMarkResolved_ForgedMarkSignature_NotAdmitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmrIssuerID)
	impostor := newFedEntity(t, tmrIssuerID) // same id, DIFFERENT key

	anchor := newFedEntity(t, tcAnchorID)
	inter := newFedEntity(t, tcInterID)

	// The mark is signed by the IMPOSTOR key (iss claims the resolved issuer id).
	mark := signTrustMark(t, impostor, leaf.id, tmType, fedClock.Unix(), 0)

	f := newFakeFetcher()
	f.configs[anchor.id] = anchorConfigWithTMI(t, anchor, tcFetchURL, map[string][]string{tmType: {issuer.id}})
	f.configs[inter.id] = inter.entityConfig(t, []string{anchor.id}, tcInterFch, nil)
	f.configs[leaf.id] = leafConfigWithTrustMarks(t, leaf, []string{inter.id},
		rpWithKeys(t, leaf, "https://rp.federation.test/cb"),
		[]federation.TrustMarkEntry{{TrustMarkType: tmType, TrustMark: mark}})
	// The issuer entity (config + chain) uses its REAL keys; the anchor vouches
	// them. The impostor-signed mark fails against the issuer's chain-vouched key.
	f.configs[issuer.id] = issuer.entityConfig(t, []string{anchor.id}, "", nil)
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = anchor.subordinateStatement(t, inter, nil)
	f.subs[subKey(tcInterFch, inter.id, leaf.id)] = inter.subordinateStatement(t, leaf, nil)
	f.subs[subKey(tcFetchURL, anchor.id, issuer.id)] = anchor.subordinateStatement(t, issuer, nil)

	store := tmStore(t, f, anchor, fedResolvedConfig([]string{tmType}))

	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(resolved issuer, forged mark signature) = %v, want ErrNoSuchClient (chain-vouched keys verify)", err)
	}
}

// ---------------------------------------------------------------------------
// FLAG OFF (default): a mark from a NON-configured issuer is REJECTED even
// though it WOULD resolve + be anchor-authorized with the flag on -> proves
// the default-off path is byte-identical to slice 4b (only configured issuers).
// ---------------------------------------------------------------------------

func TestTrustMarkResolved_FlagOff_ResolvableIssuerStillRejected(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmrIssuerID)

	// A federation set where the issuer chains + the anchor authorizes it — so the
	// federation-resolved path WOULD admit it IF enabled.
	anchorTMI := map[string][]string{tmType: {issuer.id}}
	f, anchor := buildResolvedIssuerFederation(t, leaf, issuer, tmType,
		fedClock.Unix(), 0, leaf.id, anchorTMI)

	// Flag OFF (the slice-4b config: no AllowFederationResolved...). The issuer is
	// NOT operator-configured -> the configured path misses -> REJECTED.
	store := tmStore(t, f, anchor, trustMarkConfig([]string{tmType})) // no issuers, flag off

	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(flag off, resolvable issuer) = %v, want ErrNoSuchClient (default-off: only configured issuers)", err)
	}
}

// ---------------------------------------------------------------------------
// FLAG ON + a CONFIGURED issuer: both paths coexist; the configured path takes
// precedence (a configured-issuer mark is admitted without any resolution).
// ---------------------------------------------------------------------------

func TestTrustMarkResolved_ConfiguredIssuerStillWorks_WithFlagOn(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	configured := newFedEntity(t, tmIssuerID) // the slice-4b operator-configured issuer

	// The leaf carries a mark from the CONFIGURED issuer; the federation is the
	// plain slice-4b topology (the configured issuer need NOT be a federation
	// member — the configured path uses operator-pinned keys).
	mark := signTrustMark(t, configured, leaf.id, tmType, fedClock.Unix(), 0)
	f, anchor := fedWithLeafMarks(t, leaf, rpWithKeys(t, leaf, "https://rp.federation.test/cb"),
		[]federation.TrustMarkEntry{{TrustMarkType: tmType, TrustMark: mark}})

	// Flag ON, AND the configured issuer is present with its pinned keys.
	store := tmStore(t, f, anchor, fedResolvedConfig([]string{tmType}, authorizedIssuerFor(t, configured)))

	if _, err := store.Get(context.Background(), leaf.id); err != nil {
		t.Fatalf("Get(configured issuer, flag on) = %v, want admitted (configured path takes precedence)", err)
	}
}

// FLAG ON: a single required type satisfied via the resolved path while the
// SAME store also has a configured issuer for a DIFFERENT id — proves the
// fallback only fires for the un-configured iss and the two coexist.
func TestTrustMarkResolved_FallbackOnlyForUnconfiguredIss(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	resolved := newFedEntity(t, tmrIssuerID)       // satisfied via the federation path
	configuredOther := newFedEntity(t, tmIssuerID) // configured, but NOT the mark's issuer

	anchorTMI := map[string][]string{tmType: {resolved.id}}
	f, anchor := buildResolvedIssuerFederation(t, leaf, resolved, tmType,
		fedClock.Unix(), 0, leaf.id, anchorTMI)

	// A configured issuer exists (for a different id) AND the flag is on. The
	// mark's iss is the resolved issuer, not the configured one -> the configured
	// path misses, the federation-resolved path admits.
	store := tmStore(t, f, anchor, fedResolvedConfig([]string{tmType}, authorizedIssuerFor(t, configuredOther)))

	if _, err := store.Get(context.Background(), leaf.id); err != nil {
		t.Fatalf("Get(resolved-path mark, unrelated configured issuer present) = %v, want admitted", err)
	}
}

// ---------------------------------------------------------------------------
// FLAG ON but NO trust anchors -> the federation-resolved path is INERT (no
// root of trust). A mark from a non-configured issuer is REJECTED (the gate is
// effectively configured-only). Proves the SDK nil-checks the resolver.
// ---------------------------------------------------------------------------

func TestTrustMarkResolved_FlagOnButResolverDisabled_Inert(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmrIssuerID)

	// Build the federation, but construct a store whose resolver has NO anchors
	// (disabled). We bypass tmStore so the resolver is inert.
	anchorTMI := map[string][]string{tmType: {issuer.id}}
	f, _ := buildResolvedIssuerFederation(t, leaf, issuer, tmType,
		fedClock.Unix(), 0, leaf.id, anchorTMI)

	// A resolver with no configured anchors (inert). The federation-resolved path
	// nil-checks Enabled() and stays dormant even with the flag on.
	disabledResolver := federation.NewTrustChainResolver(&federation.Config{},
		federation.WithTrustChainFetcher(f),
		federation.WithTrustChainClock(func() time.Time { return fedClock }),
	)
	store := federation.NewRegistrationClientStore(
		newCountingClientStore(),
		disabledResolver,
		federation.WithRegistrationClock(func() time.Time { return fedClock }),
		federation.WithRegistrationTrustMarks(fedResolvedConfig([]string{tmType})),
	)

	// With an inert resolver the whole federation fallback is off (the decorator
	// is a pass-through), so the leaf is simply an unknown client.
	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(flag on, resolver disabled) = %v, want ErrNoSuchClient (path inert without anchors)", err)
	}
}
