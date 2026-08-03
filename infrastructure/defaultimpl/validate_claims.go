package defaultimpl

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
)

// claimsFromPayload maps a decoded wire payload onto the public TokenClaims.
// Shared verbatim across the ECDSA/Ed25519/RSA issuers — the mapping is
// identical, so it lives here once. Defensive copies (AMR, AuthorizationDetails,
// RequestedClaims) are preserved so a caller can't mutate issuer-internal state.
func claimsFromPayload(p ed25519Payload, typ string) *sso.TokenClaims {
	claims := &sso.TokenClaims{
		TokenUse:  tokenUseFromPayload(p, typ),
		Subject:   p.Sub,
		Issuer:    p.Iss,
		Audience:  []string(p.Aud),
		Resources: append([]string(nil), p.GrantedResources...),
		ExpiresAt: time.Unix(p.Exp, 0),
		NotBefore: time.Unix(p.Nbf, 0),
		IssuedAt:  time.Unix(p.Iat, 0),
		Extra:     p.Extra,
		ClientID:  p.ClientID,
		JTI:       p.JTI,
		ACR:       p.ACR,
		AMR:       append([]string(nil), p.AMR...),
		SID:       p.SID,
		// Mint-region evidence round-trips into the validated view; the
		// introspector echoes it onto the RFC 7662 body.
		ServingRegion: p.ServingRegion,
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

func tokenUseFromPayload(p ed25519Payload, typ string) core.TokenUse {
	switch typ {
	case jwtTypAT, "application/at+jwt":
		return core.TokenUseAccessToken
	case jwtTyp:
		// Older access tokens also used typ=JWT. Their RFC 9068-only claims
		// distinguish them from an OIDC ID token while preserving upgrade
		// compatibility for in-flight tokens.
		if p.ClientID != "" || p.JTI != "" || p.CNF != nil {
			return core.TokenUseAccessToken
		}
		return core.TokenUseIDToken
	default:
		return core.TokenUseUnknown
	}
}
