package federation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/federation"
)

// ===========================================================================
// SLICE 4b — OpenID Federation 1.0 §7 TRUST MARKS as an EXTRA auto-registration
// admission requirement. Reuses the slice-2/3 FAKE federation harness
// (fedEntity / fakeFetcher / buildLinearFederationWithLeaf / fedClock): a real
// Ed25519 federation, real issuer-signed marks, a fixed clock, no network.
//
// These prove the trust-mark gate: a VALID required mark (configured authorized
// issuer, sub==RP, fresh, correct SIGNED type) ADMITS the RP; a missing /
// forged / unauthorized-issuer / wrong-type-for-issuer / wrong-subject /
// expired / future / wrong-signed-type mark leaves the RP UNKNOWN (oracle-safe,
// the slice-3 path); and an empty RequiredTrustMarkTypes is byte-identical to
// slice 3 (an RP with NO marks is admitted exactly as before).
// ===========================================================================

const (
	tmType        = "https://federation.test/trust-mark/certified-rp"
	tmTypeOther   = "https://federation.test/trust-mark/other"
	tmIssuerID    = "https://trust-mark-issuer.federation.test"
	tmIssuerOther = "https://other-issuer.federation.test"
)

// signTrustMark signs a §7 Trust Mark JWT (typ trust-mark+jwt) with the given
// issuer's key. sub is the entity the mark is about; markType is the SIGNED
// trust_mark_type. iat/exp are Unix seconds (exp==0 omits the claim). Built via
// the SAME real SignJWT seam the entities use, so the mark is genuinely signed
// by issuer's key and verifies against issuer's published JWKS.
func signTrustMark(t *testing.T, issuer *fedEntity, sub, markType string, iat, exp int64) string {
	t.Helper()
	claims := map[string]any{
		"iss":             issuer.id,
		"sub":             sub,
		"trust_mark_type": markType,
		"iat":             iat,
	}
	if exp > 0 {
		claims["exp"] = exp
	}
	compact, err := issuer.iss.SignJWT(context.Background(), federation.TrustMarkTyp, claims)
	if err != nil {
		t.Fatalf("sign trust mark (%s about %s): %v", issuer.id, sub, err)
	}
	return compact
}

// leafConfigWithTrustMarks builds + signs `leaf`'s Entity Configuration with the
// given RP metadata AND the given §7 trust_marks array. Mirrors the harness's
// entityConfig but threads trust_marks (which entityConfig does not set), so a
// leaf can carry conformance marks.
func leafConfigWithTrustMarks(t *testing.T, leaf *fedEntity, hints []string, rp map[string]any, marks []federation.TrustMarkEntry) string {
	t.Helper()
	claims := federation.EntityStatementClaims{
		Iss:            leaf.id,
		Sub:            leaf.id,
		Iat:            fedClock.Unix(),
		Exp:            fedClock.Add(24 * time.Hour).Unix(),
		JWKS:           federation.EntityJWKS{Keys: leaf.keys(t)},
		Metadata:       &federation.EntityMetadata{RP: rp},
		AuthorityHints: hints,
		TrustMarks:     marks,
	}
	return leaf.signStatement(t, claims)
}

// fedWithLeafMarks wires anchor -> intermediate -> leaf (the slice-3 linear
// federation) but with the leaf carrying the given trust_marks. Returns the
// fetcher + anchor (the rest of the topology mirrors buildLinearFederation).
func fedWithLeafMarks(t *testing.T, leaf *fedEntity, rp map[string]any, marks []federation.TrustMarkEntry) (*fakeFetcher, *fedEntity) {
	t.Helper()
	anchor := newFedEntity(t, tcAnchorID)
	inter := newFedEntity(t, tcInterID)

	f := newFakeFetcher()
	f.configs[anchor.id] = anchor.entityConfig(t, nil, tcFetchURL, nil)
	f.configs[inter.id] = inter.entityConfig(t, []string{anchor.id}, tcInterFch, nil)
	f.configs[leaf.id] = leafConfigWithTrustMarks(t, leaf, []string{inter.id}, rp, marks)
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = anchor.subordinateStatement(t, inter, nil)
	f.subs[subKey(tcInterFch, inter.id, leaf.id)] = inter.subordinateStatement(t, leaf, nil)
	return f, anchor
}

// trustMarkConfig is the federation Config the registration store's trust-mark
// gate is compiled from: the required types + the authorized issuers (each with
// its real published keys). maxClockSkew is left at the SDK default.
func trustMarkConfig(requiredTypes []string, issuers ...federation.TrustMarkIssuer) *federation.Config {
	return &federation.Config{
		RequiredTrustMarkTypes: requiredTypes,
		TrustMarkIssuers:       issuers,
	}
}

// tmStore builds a RegistrationClientStore over a real inner store + the slice-2
// resolver wired to the fake federation + the §7 trust-mark gate from cfg, all
// sharing the fixed clock.
func tmStore(t *testing.T, fetcher federation.EntityStatementFetcher, anchor *fedEntity, cfg *federation.Config) *federation.RegistrationClientStore {
	t.Helper()
	return federation.NewRegistrationClientStore(
		newCountingClientStore(),
		resolverFor(t, fetcher, anchor),
		federation.WithRegistrationClock(func() time.Time { return fedClock }),
		federation.WithRegistrationTrustMarks(cfg),
	)
}

// authorizedIssuerFor returns a TrustMarkIssuer authorizing `issuer` (its real
// keys) for the given types (empty -> any type).
func authorizedIssuerFor(t *testing.T, issuer *fedEntity, allowedTypes ...string) federation.TrustMarkIssuer {
	t.Helper()
	return federation.TrustMarkIssuer{
		EntityID:     issuer.id,
		Keys:         issuer.keys(t),
		AllowedTypes: allowedTypes,
	}
}

// ---------------------------------------------------------------------------
// VALID required mark -> ADMITTED (the slice-3 registration proceeds).
// ---------------------------------------------------------------------------

func TestTrustMark_ValidRequiredMark_Admitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmIssuerID)

	mark := signTrustMark(t, issuer, leaf.id, tmType, fedClock.Unix(), fedClock.Add(24*time.Hour).Unix())
	f, anchor := fedWithLeafMarks(t, leaf, rpWithKeys(t, leaf, "https://rp.federation.test/cb"),
		[]federation.TrustMarkEntry{{TrustMarkType: tmType, TrustMark: mark}})

	store := tmStore(t, f, anchor, trustMarkConfig([]string{tmType}, authorizedIssuerFor(t, issuer)))

	client, err := store.Get(context.Background(), leaf.id)
	if err != nil {
		t.Fatalf("Get(RP with valid trust mark) = %v, want a derived client (admitted)", err)
	}
	if client.ID != leaf.id || !client.Federation {
		t.Errorf("derived client = %+v, want the federation client for the RP", client)
	}
}

// A required mark whose issuer is configured with AllowedTypes that PERMIT the
// type (an explicit type authorization, not the empty "any") is admitted.
func TestTrustMark_AllowedTypesPermitsType_Admitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmIssuerID)

	mark := signTrustMark(t, issuer, leaf.id, tmType, fedClock.Unix(), 0)
	f, anchor := fedWithLeafMarks(t, leaf, rpWithKeys(t, leaf, "https://rp.federation.test/cb"),
		[]federation.TrustMarkEntry{{TrustMarkType: tmType, TrustMark: mark}})

	// Issuer authorized for EXACTLY this type.
	store := tmStore(t, f, anchor, trustMarkConfig([]string{tmType}, authorizedIssuerFor(t, issuer, tmType)))

	if _, err := store.Get(context.Background(), leaf.id); err != nil {
		t.Fatalf("Get(issuer explicitly authorized for the type) = %v, want admitted", err)
	}
}

// Multiple required types, each satisfied by its own valid mark -> admitted.
func TestTrustMark_MultipleRequiredTypes_AllPresent_Admitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmIssuerID)

	m1 := signTrustMark(t, issuer, leaf.id, tmType, fedClock.Unix(), 0)
	m2 := signTrustMark(t, issuer, leaf.id, tmTypeOther, fedClock.Unix(), 0)
	f, anchor := fedWithLeafMarks(t, leaf, rpWithKeys(t, leaf, "https://rp.federation.test/cb"),
		[]federation.TrustMarkEntry{
			{TrustMarkType: tmType, TrustMark: m1},
			{TrustMarkType: tmTypeOther, TrustMark: m2},
		})

	store := tmStore(t, f, anchor, trustMarkConfig([]string{tmType, tmTypeOther}, authorizedIssuerFor(t, issuer)))

	if _, err := store.Get(context.Background(), leaf.id); err != nil {
		t.Fatalf("Get(RP with both required marks) = %v, want admitted", err)
	}
}

// ---------------------------------------------------------------------------
// MISSING the required mark -> NOT admitted (unknown-client, oracle-safe).
// ---------------------------------------------------------------------------

func TestTrustMark_MissingRequiredMark_NotAdmitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmIssuerID)

	// Leaf carries NO trust marks at all.
	f, anchor := fedWithLeafMarks(t, leaf, rpWithKeys(t, leaf, "https://rp.federation.test/cb"), nil)
	store := tmStore(t, f, anchor, trustMarkConfig([]string{tmType}, authorizedIssuerFor(t, issuer)))

	_, err := store.Get(context.Background(), leaf.id)
	if !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(RP missing required mark) = %v, want ErrNoSuchClient (oracle-safe unknown-client)", err)
	}
}

// One of two required types present, the other missing -> NOT admitted (EVERY
// required type must be satisfied).
func TestTrustMark_OneOfTwoRequiredMissing_NotAdmitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmIssuerID)

	// Only tmType present; tmTypeOther required but absent.
	m1 := signTrustMark(t, issuer, leaf.id, tmType, fedClock.Unix(), 0)
	f, anchor := fedWithLeafMarks(t, leaf, rpWithKeys(t, leaf, "https://rp.federation.test/cb"),
		[]federation.TrustMarkEntry{{TrustMarkType: tmType, TrustMark: m1}})

	store := tmStore(t, f, anchor, trustMarkConfig([]string{tmType, tmTypeOther}, authorizedIssuerFor(t, issuer)))

	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(one required type missing) = %v, want ErrNoSuchClient", err)
	}
}

// ---------------------------------------------------------------------------
// UNAUTHORIZED issuer (iss not in the configured set) -> NOT admitted.
// ---------------------------------------------------------------------------

func TestTrustMark_UnauthorizedIssuer_NotAdmitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	authorized := newFedEntity(t, tmIssuerID)
	rogue := newFedEntity(t, tmIssuerOther) // a real, well-formed issuer, just NOT configured

	// The mark is genuinely signed by the rogue issuer's key (valid signature,
	// right subject, right type, fresh) — the ONLY defect is that iss is not in
	// the configured authorized set.
	mark := signTrustMark(t, rogue, leaf.id, tmType, fedClock.Unix(), 0)
	f, anchor := fedWithLeafMarks(t, leaf, rpWithKeys(t, leaf, "https://rp.federation.test/cb"),
		[]federation.TrustMarkEntry{{TrustMarkType: tmType, TrustMark: mark}})

	// Only `authorized` is configured; the rogue's marks must not satisfy.
	store := tmStore(t, f, anchor, trustMarkConfig([]string{tmType}, authorizedIssuerFor(t, authorized)))

	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(mark from unauthorized issuer) = %v, want ErrNoSuchClient (only configured authorized issuers satisfy)", err)
	}
}

// ---------------------------------------------------------------------------
// Configured issuer NOT authorized for THIS type (AllowedTypes excludes it)
// -> NOT admitted.
// ---------------------------------------------------------------------------

func TestTrustMark_IssuerNotAuthorizedForType_NotAdmitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmIssuerID)

	// The mark's SIGNED type is tmType, but the configured issuer is authorized
	// ONLY for tmTypeOther — it may not vouch for tmType.
	mark := signTrustMark(t, issuer, leaf.id, tmType, fedClock.Unix(), 0)
	f, anchor := fedWithLeafMarks(t, leaf, rpWithKeys(t, leaf, "https://rp.federation.test/cb"),
		[]federation.TrustMarkEntry{{TrustMarkType: tmType, TrustMark: mark}})

	store := tmStore(t, f, anchor, trustMarkConfig([]string{tmType}, authorizedIssuerFor(t, issuer, tmTypeOther)))

	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(issuer not authorized for the type) = %v, want ErrNoSuchClient", err)
	}
}

// ---------------------------------------------------------------------------
// FORGED mark (wrong-key signature) -> NOT admitted.
// ---------------------------------------------------------------------------

func TestTrustMark_ForgedSignature_NotAdmitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	// The authorized issuer's IDENTITY is tmIssuerID, but the mark is signed by a
	// DIFFERENT keypair (an impostor sharing the id) — iss matches the configured
	// issuer yet the signature does NOT verify against the configured keys.
	authorized := newFedEntity(t, tmIssuerID)
	impostor := newFedEntity(t, tmIssuerID) // same id, different key

	mark := signTrustMark(t, impostor, leaf.id, tmType, fedClock.Unix(), 0)
	f, anchor := fedWithLeafMarks(t, leaf, rpWithKeys(t, leaf, "https://rp.federation.test/cb"),
		[]federation.TrustMarkEntry{{TrustMarkType: tmType, TrustMark: mark}})

	// Configured with the REAL issuer's keys; the impostor-signed mark fails the
	// signature check.
	store := tmStore(t, f, anchor, trustMarkConfig([]string{tmType}, authorizedIssuerFor(t, authorized)))

	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(forged-signature mark) = %v, want ErrNoSuchClient (a forged mark must not admit)", err)
	}
}

// A structurally-tampered mark (a flipped signature byte) is also rejected.
func TestTrustMark_TamperedSignature_NotAdmitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmIssuerID)

	good := signTrustMark(t, issuer, leaf.id, tmType, fedClock.Unix(), 0)
	tampered := good[:len(good)-2] + flipChar(good[len(good)-2:len(good)-1]) + good[len(good)-1:]
	f, anchor := fedWithLeafMarks(t, leaf, rpWithKeys(t, leaf, "https://rp.federation.test/cb"),
		[]federation.TrustMarkEntry{{TrustMarkType: tmType, TrustMark: tampered}})

	store := tmStore(t, f, anchor, trustMarkConfig([]string{tmType}, authorizedIssuerFor(t, issuer)))

	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(tampered mark) = %v, want ErrNoSuchClient", err)
	}
}

// ---------------------------------------------------------------------------
// CONFUSED DEPUTY: a VALID mark about a DIFFERENT subject -> NOT admitted.
// ---------------------------------------------------------------------------

func TestTrustMark_WrongSubject_ConfusedDeputy_NotAdmitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmIssuerID)
	otherEntity := "https://some-other-rp.federation.test"

	// A perfectly valid mark — authorized issuer, fresh, correct type — but its
	// sub is a DIFFERENT entity. Presenting it in THIS leaf's config must NOT
	// admit this leaf (the classic confused-deputy).
	mark := signTrustMark(t, issuer, otherEntity, tmType, fedClock.Unix(), 0)
	f, anchor := fedWithLeafMarks(t, leaf, rpWithKeys(t, leaf, "https://rp.federation.test/cb"),
		[]federation.TrustMarkEntry{{TrustMarkType: tmType, TrustMark: mark}})

	store := tmStore(t, f, anchor, trustMarkConfig([]string{tmType}, authorizedIssuerFor(t, issuer)))

	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(mark about a different subject) = %v, want ErrNoSuchClient (confused-deputy closed)", err)
	}
}

// ---------------------------------------------------------------------------
// EXPIRED mark -> NOT admitted; FUTURE-iat mark -> NOT admitted.
// ---------------------------------------------------------------------------

func TestTrustMark_Expired_NotAdmitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmIssuerID)

	// exp 2h before the fixed clock (well past the 60s skew).
	mark := signTrustMark(t, issuer, leaf.id, tmType,
		fedClock.Add(-3*time.Hour).Unix(), fedClock.Add(-2*time.Hour).Unix())
	f, anchor := fedWithLeafMarks(t, leaf, rpWithKeys(t, leaf, "https://rp.federation.test/cb"),
		[]federation.TrustMarkEntry{{TrustMarkType: tmType, TrustMark: mark}})

	store := tmStore(t, f, anchor, trustMarkConfig([]string{tmType}, authorizedIssuerFor(t, issuer)))

	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(expired mark) = %v, want ErrNoSuchClient", err)
	}
}

func TestTrustMark_FutureIat_NotAdmitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmIssuerID)

	// iat 2h in the FUTURE (well beyond the 60s skew) -> not yet valid.
	mark := signTrustMark(t, issuer, leaf.id, tmType, fedClock.Add(2*time.Hour).Unix(), 0)
	f, anchor := fedWithLeafMarks(t, leaf, rpWithKeys(t, leaf, "https://rp.federation.test/cb"),
		[]federation.TrustMarkEntry{{TrustMarkType: tmType, TrustMark: mark}})

	store := tmStore(t, f, anchor, trustMarkConfig([]string{tmType}, authorizedIssuerFor(t, issuer)))

	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(future-iat mark) = %v, want ErrNoSuchClient", err)
	}
}

// A mark with NO iat claim at all -> NOT admitted (iat is REQUIRED).
func TestTrustMark_NoIat_NotAdmitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmIssuerID)

	// Sign a mark WITHOUT iat (iat=0 omits it via signTrustMark's claims map...
	// but signTrustMark always sets iat; build the claims directly here).
	claims := map[string]any{
		"iss":             issuer.id,
		"sub":             leaf.id,
		"trust_mark_type": tmType,
		// no iat
	}
	mark, err := issuer.iss.SignJWT(context.Background(), federation.TrustMarkTyp, claims)
	if err != nil {
		t.Fatalf("sign no-iat mark: %v", err)
	}
	f, anchor := fedWithLeafMarks(t, leaf, rpWithKeys(t, leaf, "https://rp.federation.test/cb"),
		[]federation.TrustMarkEntry{{TrustMarkType: tmType, TrustMark: mark}})

	store := tmStore(t, f, anchor, trustMarkConfig([]string{tmType}, authorizedIssuerFor(t, issuer)))

	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(no-iat mark) = %v, want ErrNoSuchClient (iat is required)", err)
	}
}

// ---------------------------------------------------------------------------
// SIGNED trust_mark_type is AUTHORITATIVE: a wrapper that CLAIMS the required
// type over a mark whose SIGNED type differs -> NOT admitted.
// ---------------------------------------------------------------------------

func TestTrustMark_SignedTypeAuthoritative_WrapperLies_NotAdmitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmIssuerID)

	// The mark is validly signed by the authorized issuer, about the right
	// subject, fresh — but its SIGNED trust_mark_type is tmTypeOther. The
	// WRAPPER entry lies, claiming it is tmType (the required type). The signed
	// type is authoritative, so this must NOT satisfy the tmType requirement.
	mark := signTrustMark(t, issuer, leaf.id, tmTypeOther, fedClock.Unix(), 0)
	f, anchor := fedWithLeafMarks(t, leaf, rpWithKeys(t, leaf, "https://rp.federation.test/cb"),
		[]federation.TrustMarkEntry{{TrustMarkType: tmType, TrustMark: mark}}) // wrapper says tmType

	// Issuer authorized broadly (any type) — so the ONLY reason to reject is the
	// signed-type mismatch, not an authorization gap.
	store := tmStore(t, f, anchor, trustMarkConfig([]string{tmType}, authorizedIssuerFor(t, issuer)))

	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(wrapper claims required type, signed type differs) = %v, want ErrNoSuchClient (signed type authoritative)", err)
	}
}

// The DUAL of the above: a correctly-SIGNED mark whose WRAPPER type is
// MISLABELED (wrapper says tmTypeOther, signed says tmType) STILL satisfies the
// tmType requirement — the wrapper type is advisory, the signed type wins.
func TestTrustMark_SignedTypeAuthoritative_WrapperMislabeled_StillAdmitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmIssuerID)

	mark := signTrustMark(t, issuer, leaf.id, tmType, fedClock.Unix(), 0) // SIGNED tmType
	f, anchor := fedWithLeafMarks(t, leaf, rpWithKeys(t, leaf, "https://rp.federation.test/cb"),
		[]federation.TrustMarkEntry{{TrustMarkType: tmTypeOther, TrustMark: mark}}) // wrapper mislabels

	store := tmStore(t, f, anchor, trustMarkConfig([]string{tmType}, authorizedIssuerFor(t, issuer)))

	if _, err := store.Get(context.Background(), leaf.id); err != nil {
		t.Fatalf("Get(correct signed type, mislabeled wrapper) = %v, want admitted (signed type authoritative)", err)
	}
}

// ---------------------------------------------------------------------------
// typ gate: a token signed by the authorized issuer key but with the WRONG typ
// (an at+jwt, not trust-mark+jwt) -> NOT admitted.
// ---------------------------------------------------------------------------

func TestTrustMark_WrongTyp_NotAdmitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmIssuerID)

	// Otherwise-perfect claims, but signed with typ at+jwt — a plain access token
	// shape, not a Trust Mark. The typ gate must reject it before trusting it.
	claims := map[string]any{
		"iss":             issuer.id,
		"sub":             leaf.id,
		"trust_mark_type": tmType,
		"iat":             fedClock.Unix(),
	}
	wrongTyp, err := issuer.iss.SignJWT(context.Background(), "at+jwt", claims)
	if err != nil {
		t.Fatalf("sign wrong-typ token: %v", err)
	}
	f, anchor := fedWithLeafMarks(t, leaf, rpWithKeys(t, leaf, "https://rp.federation.test/cb"),
		[]federation.TrustMarkEntry{{TrustMarkType: tmType, TrustMark: wrongTyp}})

	store := tmStore(t, f, anchor, trustMarkConfig([]string{tmType}, authorizedIssuerFor(t, issuer)))

	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(wrong-typ token as mark) = %v, want ErrNoSuchClient (typ gate)", err)
	}
}

// ---------------------------------------------------------------------------
// DEFAULT-OFF byte-identical: no RequiredTrustMarkTypes -> an RP with NO trust
// marks is admitted exactly as slice-3 today (the gate is inert).
// ---------------------------------------------------------------------------

func TestTrustMark_DefaultOff_NoRequiredTypes_AdmitsWithoutMarks(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	// No trust marks on the leaf, AND no required types configured.
	f, anchor := fedWithLeafMarks(t, leaf, rpWithKeys(t, leaf, "https://rp.federation.test/cb"), nil)

	// Empty RequiredTrustMarkTypes -> the gate is OFF (byte-identical to slice 3).
	store := tmStore(t, f, anchor, trustMarkConfig(nil))

	client, err := store.Get(context.Background(), leaf.id)
	if err != nil {
		t.Fatalf("Get(RP, no required types) = %v, want admitted exactly as slice 3 (default-off)", err)
	}
	if client == nil || client.ID != leaf.id || !client.Federation {
		t.Errorf("derived client = %+v, want the slice-3 federation client", client)
	}
}

// Even with a nil Config passed to WithRegistrationTrustMarks, the gate is inert
// (default-off) — an RP with no marks is admitted.
func TestTrustMark_NilConfig_Inert_AdmitsWithoutMarks(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	f, anchor := fedWithLeafMarks(t, leaf, rpWithKeys(t, leaf, "https://rp.federation.test/cb"), nil)

	store := federation.NewRegistrationClientStore(
		newCountingClientStore(),
		resolverFor(t, f, anchor),
		federation.WithRegistrationClock(func() time.Time { return fedClock }),
		federation.WithRegistrationTrustMarks(nil), // nil cfg -> inert
	)

	if _, err := store.Get(context.Background(), leaf.id); err != nil {
		t.Fatalf("Get with nil trust-mark cfg = %v, want admitted (inert gate)", err)
	}
}

// A store with NO trust-mark option wired at all behaves identically (the
// zero-value gate is nil/inert) — proves the slice-3 store is unaffected.
func TestTrustMark_OptionAbsent_SliceThreeUnaffected(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	f, anchor := fedWithLeafMarks(t, leaf, rpWithKeys(t, leaf, "https://rp.federation.test/cb"), nil)

	store := federation.NewRegistrationClientStore(
		newCountingClientStore(),
		resolverFor(t, f, anchor),
		federation.WithRegistrationClock(func() time.Time { return fedClock }),
		// no WithRegistrationTrustMarks at all
	)

	if _, err := store.Get(context.Background(), leaf.id); err != nil {
		t.Fatalf("Get without the trust-mark option = %v, want admitted (slice-3 unaffected)", err)
	}
}

// ---------------------------------------------------------------------------
// Additive: a VALID mark does NOT bypass the slice-2 chain. An INVALID chain
// stays unknown REGARDLESS of a present, valid trust mark (the trust-mark gate
// only ADDS a requirement; it never relaxes the chain requirement).
// ---------------------------------------------------------------------------

func TestTrustMark_ValidMarkDoesNotBypassInvalidChain(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	anchor := newFedEntity(t, tcAnchorID)
	rogue := newFedEntity(t, "https://rogue.federation.test")
	issuer := newFedEntity(t, tmIssuerID)

	// A perfectly valid trust mark for the leaf...
	mark := signTrustMark(t, issuer, leaf.id, tmType, fedClock.Unix(), 0)

	// ...but the leaf's chain NEVER reaches the configured anchor (its only hint
	// is a rogue non-anchor with no path up). Resolution fails BEFORE the
	// trust-mark gate is ever consulted.
	f := newFakeFetcher()
	f.configs[anchor.id] = anchor.entityConfig(t, nil, tcFetchURL, nil)
	f.configs[rogue.id] = rogue.entityConfig(t, nil, "https://rogue.federation.test/fetch", nil)
	f.configs[leaf.id] = leafConfigWithTrustMarks(t, leaf, []string{rogue.id},
		rpWithKeys(t, leaf, "https://rp.federation.test/cb"),
		[]federation.TrustMarkEntry{{TrustMarkType: tmType, TrustMark: mark}})
	f.subs[subKey("https://rogue.federation.test/fetch", rogue.id, leaf.id)] = rogue.subordinateStatement(t, leaf, nil)

	store := tmStore(t, f, anchor, trustMarkConfig([]string{tmType}, authorizedIssuerFor(t, issuer)))

	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Errorf("Get(valid mark, invalid chain) = %v, want ErrNoSuchClient (a mark cannot bypass the chain)", err)
	}
}

// ---------------------------------------------------------------------------
// One valid + one junk wrapper entry for the SAME required type: the gate scans
// every entry and is satisfied by the valid one (the junk entry is skipped).
// ---------------------------------------------------------------------------

func TestTrustMark_ValidAmongJunkEntries_Admitted(t *testing.T) {
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmIssuerID)

	valid := signTrustMark(t, issuer, leaf.id, tmType, fedClock.Unix(), 0)
	f, anchor := fedWithLeafMarks(t, leaf, rpWithKeys(t, leaf, "https://rp.federation.test/cb"),
		[]federation.TrustMarkEntry{
			{TrustMarkType: tmType, TrustMark: "not-a-jws"}, // junk, skipped
			{TrustMarkType: tmType, TrustMark: ""},          // empty, skipped
			{TrustMarkType: tmType, TrustMark: valid},       // the real one
		})

	store := tmStore(t, f, anchor, trustMarkConfig([]string{tmType}, authorizedIssuerFor(t, issuer)))

	if _, err := store.Get(context.Background(), leaf.id); err != nil {
		t.Fatalf("Get(valid mark among junk entries) = %v, want admitted (gate scans all entries)", err)
	}
}
