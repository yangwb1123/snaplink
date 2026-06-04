package federation

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/security"
)

// OpenID Federation 1.0 §7 (Trust Marks) — an EXTRA admission requirement for
// automatic registration. A Trust Mark is a signed conformance assertion ("this
// RP is certified for X") minted by a Trust Mark Issuer. A federation operator
// can REQUIRE that an auto-registering RP carry a valid Trust Mark of each
// configured type, else the RP is not admitted — layered ON TOP of the slice-3
// trust-chain gate (slice 4b), additive (only STRICTER) and fail-closed.
//
// THE TRUST DECISION — what makes a required mark satisfied:
//
//   - Only a CONFIGURED AUTHORIZED issuer can satisfy a requirement. The mark's
//     `iss` MUST match a configured TrustMarkIssuer, that issuer MUST be
//     authorized for the type (AllowedTypes), and the mark's signature MUST
//     verify against the issuer's CONFIGURED keys (the operator pins the keys —
//     the federation-resolved trust_mark_issuers-key path is a follow-on). A
//     mark from an unknown issuer, a known-but-unauthorized-for-this-type
//     issuer, or a forged/wrong-key signature does NOT satisfy the requirement.
//   - `sub` MUST equal the RP (leaf) entity ID — the confused-deputy guard: a
//     genuine mark issued ABOUT entity A must NOT admit entity B. This is the
//     classic trust-mark binding; omitting it would let any federation member
//     present someone else's certification.
//   - The SIGNED `trust_mark_type` is AUTHORITATIVE (the unsigned wrapper entry
//     type is only a navigation hint): the mark satisfies a required type only
//     if the type CLAIM inside the signature-validated JWT equals it. A wrapper
//     that relabels a mark cannot launder it into a different type.
//   - typ == trust-mark+jwt (the §7 Trust Mark JOSE type) — so a plain
//     access/id token (or an entity statement) signed by the issuer key can
//     never be accepted as a Trust Mark.
//   - iat present + not in the future (bounded skew); exp (if present) not
//     expired (bounded skew) — a stale/future-dated mark is rejected.
//
// FAIL-CLOSED + ORACLE-SAFE: any missing / forged / unauthorized / expired /
// wrong-subject / wrong-type required mark returns an error; the registration
// gate maps that to the SAME slice-3 unknown-client path (the RP stays unknown,
// the specific cause to the log, never the wire — no trust-mark-specific wire
// signal). DEFAULT-OFF: an empty required-types set skips this entirely
// (byte-identical to the slice-3 path).

// TrustMarkTyp is the REQUIRED JOSE `typ` header of a §7 Trust Mark JWT. The
// gate asserts it BEFORE trusting any claim, so a token of another shape signed
// by the issuer's key (an id_token, an entity statement) cannot masquerade as a
// Trust Mark — mirroring the entity-statement+jwt typ discipline.
const TrustMarkTyp = "trust-mark+jwt"

// ErrTrustMarkRequirementUnmet is the single coarse error every trust-mark
// admission failure collapses into (a required type with no valid mark:
// missing, forged, unauthorized issuer, wrong subject, wrong signed type, or
// expired). Like ErrTrustChainInvalid it is oracle-reasonable: the registration
// gate maps it to the wrapped store's unknown-client miss, so the wire shape is
// byte-identical to any unknown client_id; the specific cause is logged.
var ErrTrustMarkRequirementUnmet = errors.New("federation: required trust mark not satisfied")

// trustMarkClaims is the payload of a §7 Trust Mark JWT. Only the members the
// gate validates are decoded; optional ref/logo_uri/delegation are ignored.
type trustMarkClaims struct {
	Iss           string `json:"iss"`
	Sub           string `json:"sub"`
	TrustMarkType string `json:"trust_mark_type"`
	Iat           int64  `json:"iat"`
	Exp           int64  `json:"exp"`
}

// trustMarkRequirement is the IMMUTABLE compiled trust-mark gate, derived from
// the federation Config once at construction and shared (read-only) across
// concurrent registrations. A nil *trustMarkRequirement (or one with no
// required types) is INERT — validate is a no-op, so the slice-3 path stays
// byte-identical (the default-off posture).
type trustMarkRequirement struct {
	// requiredTypes are the Trust Mark Type URIs an RP MUST each satisfy. Empty
	// ⇒ inert.
	requiredTypes []string
	// issuers are the operator-AUTHORIZED Trust Mark Issuers — the only issuers
	// whose signed marks can satisfy a requirement.
	issuers []TrustMarkIssuer
	// allowedAlgs is the asymmetric signing-alg allowlist passed to
	// security.VerifyCompactJWS (a federation/trust-mark signing key is
	// asymmetric; the verifier refuses any symmetric alg or alg=none regardless).
	allowedAlgs map[string]struct{}
	// skew widens the iat/exp freshness window (clock drift between this server
	// and the Trust Mark Issuer).
	skew time.Duration
}

// newTrustMarkRequirement compiles the trust-mark gate from a Config. Returns
// nil when the gate is OFF (nil cfg or no RequiredTrustMarkTypes), so callers
// can nil-check for the byte-identical default-off path. The alg allowlist
// mirrors the trust-chain resolver's (the full asymmetric set;
// VerifyCompactJWS refuses symmetric/none regardless).
func newTrustMarkRequirement(cfg *Config) *trustMarkRequirement {
	if cfg == nil || len(cfg.RequiredTrustMarkTypes) == 0 {
		return nil
	}
	return &trustMarkRequirement{
		requiredTypes: append([]string(nil), cfg.RequiredTrustMarkTypes...),
		issuers:       cfg.TrustMarkIssuers,
		allowedAlgs:   federationAsymmetricAlgs(),
		skew:          cfg.maxClockSkew(),
	}
}

// enabled reports whether the gate is live (at least one required type). A nil
// receiver is inert.
func (r *trustMarkRequirement) enabled() bool {
	return r != nil && len(r.requiredTypes) > 0
}

// validate enforces the §7 requirement: for EACH required type the leaf MUST
// carry at least one mark that fully validates (authorized configured issuer +
// signature + sub==leaf + signed-type==required + typ + fresh). Returns nil
// when every required type is satisfied, else ErrTrustMarkRequirementUnmet
// (fail-closed; the specific cause goes to logError, never the caller). A nil/
// inert receiver returns nil (no requirement) so the slice-3 path is unchanged.
//
// now is injected (not time.Now) so a test drives a fixed instant through both
// the minted mark's iat/exp AND this check — no real-clock date bomb.
func (r *trustMarkRequirement) validate(leafEntityID string, marks []TrustMarkEntry, now time.Time, logError func(msg string, args ...any)) error {
	if !r.enabled() {
		return nil
	}
	if logError == nil {
		logError = func(string, ...any) {}
	}
	for _, reqType := range r.requiredTypes {
		if !r.satisfiedBy(leafEntityID, reqType, marks, now, logError) {
			// One unmet required type fails the whole admission (fail-closed). The
			// per-candidate cause was already logged inside satisfiedBy.
			logError("federation: required trust mark not satisfied", "leaf", leafEntityID, "trust_mark_type", reqType)
			return fmt.Errorf("%w: type %q", ErrTrustMarkRequirementUnmet, reqType)
		}
	}
	return nil
}

// satisfiedBy reports whether ANY of the leaf's trust_marks entries is a VALID
// mark for reqType. It iterates EVERY entry and fully validates each (the
// unsigned wrapper type is NOT used as a gate — only as a cheap pre-filter
// skip; the authoritative match is the SIGNED type == reqType inside
// validateMark). So a correctly-signed mark satisfies even if its wrapper type
// is mislabeled, and a wrapper that merely CLAIMS reqType over a different
// signed type does NOT satisfy (the signed type is authoritative).
func (r *trustMarkRequirement) satisfiedBy(leafEntityID, reqType string, marks []TrustMarkEntry, now time.Time, logError func(msg string, args ...any)) bool {
	for i := range marks {
		if err := r.validateMark(leafEntityID, reqType, marks[i].TrustMark, now); err != nil {
			// Not a valid mark FOR THIS TYPE (wrong type, wrong subject, forged,
			// unauthorized issuer, expired, ...). Log + keep looking — another
			// entry may satisfy this type.
			logError("federation: trust mark candidate rejected", "leaf", leafEntityID, "trust_mark_type", reqType, "error", err)
			continue
		}
		return true
	}
	return false
}

// validateMark fully validates a single compact Trust Mark JWS as satisfying
// reqType for leafEntityID. The order is security-deliberate: cheap structural
// + typ checks, then resolve the AUTHORIZED issuer by the (unverified) iss,
// then VERIFY THE SIGNATURE against that issuer's configured keys (the trust
// gate), and only AFTER the signature holds do the claim bindings (sub, signed
// type, freshness) — so every trusted claim comes from a signature-validated
// mark. Returns nil only when the mark is a valid, authorized, fresh, correctly-
// bound mark of reqType.
func (r *trustMarkRequirement) validateMark(leafEntityID, reqType, compact string, now time.Time) error {
	if compact == "" {
		return errors.New("empty trust mark")
	}
	// typ gate FIRST (before any signature work): a non-trust-mark+jwt token
	// signed by the issuer key (an id_token, an entity statement) must not be
	// accepted as a Trust Mark.
	typ, err := jwsHeaderTyp(compact)
	if err != nil {
		return fmt.Errorf("trust mark header: %w", err)
	}
	if typ != TrustMarkTyp {
		return fmt.Errorf("trust mark typ %q != %q", typ, TrustMarkTyp)
	}

	// Parse the UNVERIFIED payload only to read `iss` (to select the authorized
	// issuer + its verification keys). This grants no trust: if iss is forged to
	// name a configured issuer, the signature check against that issuer's REAL
	// keys below fails (the attacker lacks the issuer's private key). This is the
	// same unverified-parse-to-navigate discipline the trust-chain resolver uses.
	payload, err := unverifiedPayload(compact)
	if err != nil {
		return fmt.Errorf("trust mark payload: %w", err)
	}
	var claims trustMarkClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("trust mark claims: %w", err)
	}

	// Resolve the AUTHORIZED issuer: a configured TrustMarkIssuer whose EntityID
	// equals the mark's iss AND whose AllowedTypes permits reqType. An iss not in
	// the configured authorized set, or one not authorized for reqType, can NEVER
	// satisfy the requirement — only configured authorized issuers can. (The
	// AllowedTypes check is on reqType, which validateMark also pins to the
	// SIGNED type below, so an issuer cannot be tricked via a relabeled wrapper.)
	issuer, ok := r.authorizedIssuer(claims.Iss, reqType)
	if !ok {
		return fmt.Errorf("trust mark issuer %q not authorized for type %q", claims.Iss, reqType)
	}

	// SIGNATURE — the trust gate. Verify against the issuer's CONFIGURED keys via
	// the shared asymmetric verifier (alg=none/symmetric-safe, kid-bound). A
	// forged or wrong-key signature fails here.
	if len(issuer.Keys) == 0 {
		return fmt.Errorf("authorized issuer %q has no configured keys", issuer.EntityID)
	}
	if _, err := security.VerifyCompactJWS(compact, issuer.Keys, r.allowedAlgs); err != nil {
		return fmt.Errorf("trust mark signature: %w", err)
	}

	// Claim bindings — now trusted (the signature held).
	//
	// sub == the RP/leaf entity ID: the confused-deputy guard. A genuine mark
	// ABOUT a DIFFERENT subject must NOT admit this RP.
	if claims.Sub != leafEntityID {
		return fmt.Errorf("trust mark sub %q != leaf entity id %q", claims.Sub, leafEntityID)
	}
	// The SIGNED trust_mark_type is AUTHORITATIVE: it MUST equal reqType. This
	// also makes the iss-AllowedTypes authorization (checked on reqType above)
	// an authorization on the SIGNED type — a wrapper cannot relabel a mark of
	// another type into reqType.
	if claims.TrustMarkType != reqType {
		return fmt.Errorf("signed trust_mark_type %q != required %q", claims.TrustMarkType, reqType)
	}
	// Freshness: iat REQUIRED and not in the future; exp (if present) not
	// expired. Both bounded by the configured skew (clock drift only).
	if err := r.checkTrustMarkFresh(claims, now); err != nil {
		return err
	}
	return nil
}

// authorizedIssuer returns the configured TrustMarkIssuer whose EntityID equals
// iss AND which is authorized for reqType (AllowedTypes empty ⇒ any type, else
// reqType must be listed). The FIRST match wins. Only an issuer matched here can
// satisfy a requirement.
func (r *trustMarkRequirement) authorizedIssuer(iss, reqType string) (TrustMarkIssuer, bool) {
	if iss == "" {
		return TrustMarkIssuer{}, false
	}
	for _, ti := range r.issuers {
		if ti.EntityID != iss {
			continue
		}
		if !typeAllowed(ti.AllowedTypes, reqType) {
			// This configured issuer exists but is NOT authorized for reqType —
			// keep scanning (a different configured entry for the same iss could
			// be authorized, though typically there is one).
			continue
		}
		return ti, true
	}
	return TrustMarkIssuer{}, false
}

// typeAllowed reports whether reqType is permitted by an issuer's AllowedTypes:
// an EMPTY list authorizes ANY type (broad trust), else the type MUST be listed.
func typeAllowed(allowedTypes []string, reqType string) bool {
	if len(allowedTypes) == 0 {
		return true
	}
	for _, t := range allowedTypes {
		if t == reqType {
			return true
		}
	}
	return false
}

// checkTrustMarkFresh enforces the §7 iat/exp window with the configured skew.
// iat is REQUIRED (a mark with no iat is rejected) and must not be in the future
// (now+skew >= iat); exp is OPTIONAL but, when present, must not be in the past
// (now-skew <= exp). The skew absorbs clock drift only.
func (r *trustMarkRequirement) checkTrustMarkFresh(claims trustMarkClaims, now time.Time) error {
	if claims.Iat <= 0 {
		return errors.New("trust mark has no iat")
	}
	iat := time.Unix(claims.Iat, 0)
	if now.Add(r.skew).Before(iat) {
		return fmt.Errorf("trust mark not yet valid (iat %d, now %d)", claims.Iat, now.Unix())
	}
	if claims.Exp > 0 {
		exp := time.Unix(claims.Exp, 0)
		if now.After(exp.Add(r.skew)) {
			return fmt.Errorf("trust mark expired at %d (now %d)", claims.Exp, now.Unix())
		}
	}
	return nil
}
