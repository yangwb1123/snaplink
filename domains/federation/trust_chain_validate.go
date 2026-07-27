package federation

import (
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

// Trust-chain TOP-DOWN signature-validation helpers (OpenID Federation 1.0 §9),
// split out of trust_chain.go so each link's verification is a small,
// independently-budgeted unit. (*TrustChainResolver).validate orchestrates them:
// the anchor config first (against the CONFIGURED keys), then each Subordinate
// Statement against the keys the link above vouched for its issuer, then the
// leaf against the keys SS_1 published for it. Behavior is identical to the
// original inlined walk — the FIRST failure is returned (fail-closed).

// verifyAnchorConfig verifies the anchor Entity Configuration (the chain's last
// link) against the CONFIGURED anchor keys (the root of trust — never the keys
// the fetched statement self-asserts), and checks it is self-signed + fresh.
func (r *TrustChainResolver) verifyAnchorConfig(last chainLink, anchor TrustAnchor, now time.Time, skew time.Duration) error {
	if len(anchor.Keys) == 0 {
		return fmt.Errorf("configured anchor %q has no keys", anchor.EntityID)
	}
	if err := r.verifyStatement(last.compact, anchor.Keys); err != nil {
		return fmt.Errorf("anchor entity configuration signature: %w", err)
	}
	if err := checkSelfSigned(last.claims, anchor.EntityID); err != nil {
		return fmt.Errorf("anchor entity configuration: %w", err)
	}
	if err := checkFresh(last.claims, now, skew); err != nil {
		return fmt.Errorf("anchor entity configuration: %w", err)
	}
	return nil
}

// verifyChainLinks walks DOWN the multi-link chain from the (already-verified)
// anchor config: every Subordinate Statement SS_n..SS_1 is verified against the
// keys vouched for its issuer by the link above, then the leaf Entity
// Configuration is verified against the keys SS_1 vouched for the leaf.
// issuerKeys/issuerID carry the keys + identity the link just verified vouches
// for the NEXT link down, seeded with the anchor config's own keys.
func (r *TrustChainResolver) verifyChainLinks(links []chainLink, anchorConfig chainLink, now time.Time, skew time.Duration) error {
	issuerKeys := anchorConfig.claims.JWKS.Keys
	issuerID := anchorConfig.claims.Sub

	// The Subordinate Statements SS_n .. SS_1 (indices len-2 down to 1).
	for i := len(links) - 2; i >= 1; i-- {
		if err := r.verifySubordinateStatement(links[i], i, issuerKeys, issuerID, now, skew); err != nil {
			return err
		}
		// The keys this SS vouches for its SUBJECT become the issuer keys for the
		// next link down (the next SS, or the leaf config at index 0).
		issuerKeys = links[i].claims.JWKS.Keys
		issuerID = links[i].claims.Sub
	}

	return r.verifyLeafConfig(links[0], issuerKeys, issuerID, now, skew)
}

// verifySubordinateStatement verifies one Subordinate Statement (at index i)
// against the keys the link above vouched for its issuer (issuerKeys/issuerID),
// checking freshness + the iss/sub relationship + a non-empty subject jwks.
func (r *TrustChainResolver) verifySubordinateStatement(ss chainLink, i int, issuerKeys []core.JWK, issuerID string, now time.Time, skew time.Duration) error {
	if err := r.verifyStatement(ss.compact, issuerKeys); err != nil {
		return fmt.Errorf("subordinate statement at %d signature: %w", i, err)
	}
	if err := checkFresh(ss.claims, now, skew); err != nil {
		return fmt.Errorf("subordinate statement at %d: %w", i, err)
	}
	// iss MUST be the entity the link above vouched for (issuerID); sub is the
	// entity below; iss != sub (a real subordinate relationship).
	if ss.claims.Iss != issuerID {
		return fmt.Errorf("subordinate statement at %d: iss %q != expected issuer %q", i, ss.claims.Iss, issuerID)
	}
	if ss.claims.Sub == "" || ss.claims.Sub == ss.claims.Iss {
		return fmt.Errorf("subordinate statement at %d: bad sub %q (empty or == iss)", i, ss.claims.Sub)
	}
	if len(ss.claims.JWKS.Keys) == 0 {
		return fmt.Errorf("subordinate statement at %d: empty subject jwks", i)
	}
	return nil
}

// verifyLeafConfig verifies the leaf Entity Configuration (index 0) against the
// keys SS_1 vouched for the leaf (issuerKeys), NOT its self-asserted keys. It is
// self-signed (iss==sub==leaf) and that identity MUST equal the subject SS_1
// vouched for (issuerID).
func (r *TrustChainResolver) verifyLeafConfig(leaf chainLink, issuerKeys []core.JWK, issuerID string, now time.Time, skew time.Duration) error {
	if err := r.verifyStatement(leaf.compact, issuerKeys); err != nil {
		return fmt.Errorf("leaf entity configuration signature: %w", err)
	}
	if err := checkFresh(leaf.claims, now, skew); err != nil {
		return fmt.Errorf("leaf entity configuration: %w", err)
	}
	if err := checkSelfSigned(leaf.claims, issuerID); err != nil {
		return fmt.Errorf("leaf entity configuration: %w", err)
	}
	return nil
}
