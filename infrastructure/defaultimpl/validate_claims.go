package defaultimpl

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
)

// claimsFromPayload maps a decoded wire payload onto the public TokenClaims.
// Shared verbatim across the ECDSA/Ed25519/RSA issuers — the mapping is
// identical, so it lives here once. Defensive copies (AMR, AuthorizationDetails,
// RequestedClaims) are preserved so a caller can't mutate issuer-internal state.
func claimsFromPayload(p ed25519Payload) *sso.TokenClaims {
	claims := &sso.TokenClaims{
		Subject:   p.Sub,
		Issuer:    p.Iss,
		Audience:  []string(p.Aud),
		ExpiresAt: time.Unix(p.Exp, 0),
		NotBefore: time.Unix(p.Nbf, 0),
		IssuedAt:  time.Unix(p.Iat, 0),
		Extra:     p.Extra,
		ClientID:  p.ClientID,
		JTI:       p.JTI,
		ACR:       p.ACR,
		AMR:       append([]string(nil), p.AMR...),
		SID:       p.SID,
	}
	if p.CNF != nil {
		claims.ConfirmationJKT = p.CNF.JKT
		claims.ConfirmationX5TS256 = p.CNF.X5TS256
	}
	if len(p.AuthorizationDetails) > 0 {
		claims.AuthorizationDetails = append(json.RawMessage(nil), p.AuthorizationDetails...)
	}
	if p.AuthTime > 0 {
		claims.AuthTime = time.Unix(p.AuthTime, 0)
	}
	if p.Scope != "" {
		claims.Scopes = strings.Split(p.Scope, " ")
	}
	if chain := wireChainToActor(p.Act); chain != nil {
		claims.Actor = chain
	}
	if len(p.RequestedClaims) > 0 {
		claims.RequestedClaims = append(json.RawMessage(nil), p.RequestedClaims...)
	}
	return claims
}
