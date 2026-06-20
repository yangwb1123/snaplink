package defaultimpl

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
)

// defaultTokenTTL is the fallback access-token lifetime shared by the
// Ed25519/ECDSA/RSA JWS issuers when no per-issuer TTL is configured.
const defaultTokenTTL = time.Hour

// buildAccessPayload assembles the full RFC 9068 §2.2 access-token claim set
// (base claims + the optional-claims projection) into the signer-independent
// ed25519Payload. Shared verbatim across the Ed25519/ECDSA/RSA issuers — the
// JSON claim set is algorithm-independent, so claim handling stays byte-for-byte
// identical across signers. The header.alg (the alg-confusion defense) is set
// by each caller, never here.
func buildAccessPayload(issuer string, subject *sso.Subject, scopes []string, jti string, now, expiresAt time.Time) ed25519Payload {
	payload := ed25519Payload{
		Iss:      issuer,
		Sub:      subject.ID,
		Exp:      expiresAt.Unix(),
		Nbf:      now.Unix(),
		Iat:      now.Unix(),
		Scope:    strings.Join(scopes, " "),
		Extra:    subject.Claims,
		ClientID: subject.ClientID,
		JTI:      jti,
		ACR:      subject.ACR,
		SID:      subject.SID,
	}
	applyOptionalClaims(&payload, subject)
	return payload
}

// effectiveAccessTTL resolves the per-issuance access-token lifetime: a
// positive Subject.TTL (Client.AccessTokenTTL) wins over the issuer's
// configured default; zero preserves backwards compatibility for callers
// that don't set Subject.TTL. Shared verbatim across the Ed25519/ECDSA/RSA
// issuers so their TTL semantics stay identical.
func effectiveAccessTTL(subject *sso.Subject, defaultTTL time.Duration) time.Duration {
	effectiveTTL := defaultTTL
	if subject.TTL > 0 {
		effectiveTTL = subject.TTL
	}
	return effectiveTTL
}

// applyOptionalClaims projects the optional RFC 9068 §2.2 access-token
// claims onto an already-populated ed25519Payload. Each `if` guard is
// wire-visible — it controls whether the claim is emitted — so every
// guard and defensive copy is preserved byte-for-byte. Shared across the
// Ed25519/ECDSA/RSA issuers because the JSON claim set is signer-independent.
func applyOptionalClaims(payload *ed25519Payload, subject *sso.Subject) {
	if subject.ConfirmationJKT != "" || subject.ConfirmationX5TS256 != "" {
		payload.CNF = &confirmationClaim{
			JKT:     subject.ConfirmationJKT,
			X5TS256: subject.ConfirmationX5TS256,
		}
	}
	if !subject.AuthTime.IsZero() {
		payload.AuthTime = subject.AuthTime.Unix()
	}
	if len(subject.AMR) > 0 {
		payload.AMR = append([]string(nil), subject.AMR...)
	}
	if len(subject.AuthorizationDetails) > 0 {
		payload.AuthorizationDetails = append(json.RawMessage(nil), subject.AuthorizationDetails...)
	}
	if chain := actorChainToWire(subject.Actor); chain != nil {
		payload.Act = chain
	}
	if len(subject.RequestedClaims) > 0 {
		payload.RequestedClaims = append(json.RawMessage(nil), subject.RequestedClaims...)
	}
	// RFC 8707 resource indicators flow through Subject.Resources into the
	// standard `aud` JWT claim. Resource servers verify their own URI is in
	// the array before accepting the token.
	if len(subject.Resources) > 0 {
		payload.Aud = audClaim(append([]string(nil), subject.Resources...))
	}
}
