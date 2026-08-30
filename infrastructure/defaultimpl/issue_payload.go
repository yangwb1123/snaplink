package defaultimpl

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
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
		Extra:    claimsWithoutEmittedKeys(subject),
		ClientID: subject.ClientID,
		JTI:      jti,
		ACR:      subject.ACR,
		SID:      subject.SID,
		// Unconditional literal assignment (SID discipline): omitempty
		// performs the omission, so no wire-visible guard is needed.
		ServingRegion: subject.ServingRegion,
		// Same discipline as ServingRegion: the client's mint-time tenant
		// binding is stamped unconditionally and omitempty omits it when
		// empty (single-tenant stays byte-identical).
		TenantID: subject.TenantID,
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

// accessTokenExpiry applies the optional RFC 8705 certificate lifetime ceiling.
// The zero-ceiling path preserves the issuer's existing TTL-derived response.
func accessTokenExpiry(now time.Time, ttl time.Duration, notAfter time.Time) (time.Time, int) {
	expiresAt := now.Add(ttl)
	expiresIn := int(ttl.Seconds())
	if !notAfter.IsZero() && notAfter.Before(expiresAt) {
		expiresAt = notAfter
		expiresIn = int(max(time.Duration(0), expiresAt.Sub(now)).Seconds())
	}
	return expiresAt, expiresIn
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
	// Roles: same guard+copy discipline as AMR — the claim is emitted only
	// when non-empty and the subject's slice is never aliased into the
	// payload (a later caller mutation must not change the signed claim set).
	if len(subject.Roles) > 0 {
		payload.Roles = append([]string(nil), subject.Roles...)
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

// claimsWithoutEmittedKeys returns subject.Claims for the token payload,
// minus any key that buildAccessPayload also emits as a top-level claim
// (tenant_id when the client is tenant-bound, roles when membership
// resolved). A token must never carry two values for one claim name — the
// mint-time binding literal wins, the attribute-bag copy is dropped. The
// caller-owned map is never mutated (token exchange passes the original
// token's Extra straight through; authcode/device/refresh pass the
// authenticator's attribute map): a copy is made only when a key actually
// needs removing, so the single-tenant hot path returns the original map
// identity with zero allocation.
func claimsWithoutEmittedKeys(subject *sso.Subject) map[string]string {
	stripTenant := subject.TenantID != ""
	stripRoles := len(subject.Roles) > 0
	if !stripTenant && !stripRoles {
		return subject.Claims
	}
	_, hasTenant := subject.Claims[core.KeyTenantID]
	_, hasRoles := subject.Claims[core.KeyRoles]
	if (!stripTenant || !hasTenant) && (!stripRoles || !hasRoles) {
		return subject.Claims
	}
	out := make(map[string]string, len(subject.Claims))
	for k, v := range subject.Claims {
		if stripTenant && k == core.KeyTenantID {
			continue
		}
		if stripRoles && k == core.KeyRoles {
			continue
		}
		out[k] = v
	}
	return out
}

// jwsSigner is the structural signing contract every {Ed25519,ECDSA,RSA}
// {Algo}Signer interface already declares (identical `Sign(ctx, message)
// ([]byte, error)` method set). Declaring it once here — rather than
// exporting a shared type the three per-algorithm Signer interfaces would
// need to embed — lets signCompactJWS accept any of them without a public
// API change; Go's structural typing does the rest.
type jwsSigner interface {
	Sign(ctx context.Context, message []byte) ([]byte, error)
}

// signingBufPool pools the scratch buffer signCompactJWS assembles a
// compact JWS into. Every {Ed25519,ECDSA,RSA} issuer's Issue /
// IssueIDToken / IssueLogoutToken / SignJWT / SignUserInfo / SignMetadata
// funnels through it, so pooling here cuts allocations on the single
// hottest path in the server: minting an access token. New always hands
// out an empty *bytes.Buffer; signCompactJWS resets it before use, so no
// caller ever observes a stale byte from a prior issuance.
var signingBufPool = sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// signCompactJWS marshals header+payload, base64url-encodes them into a
// pooled buffer, signs the assembled signing input, and appends the
// base64url signature — producing the exact "header.payload.signature"
// compact JWS every issuer minted before this helper existed: same
// json.Marshal calls, same base64.RawURLEncoding, same '.' separators,
// only the intermediate allocations change. A json.Marshal error is
// returned unwrapped (matching the pre-pooling per-issuer helpers, which
// never wrapped it — realistically unreachable since every header/payload
// here is a fixed, always-serializable struct or a pass-through
// json.RawMessage); a Sign error is wrapped with errPrefix, matching each
// issuer's former inline ": %w" wrap byte-for-byte.
//
// The pooled buffer backs the slice handed to sgn.Sign. That's safe
// because every {Algo}Signer in this codebase signs SYNCHRONOUSLY and
// never retains the message slice past the call returning: the software
// signers hash/sign in place (crypto/ed25519, crypto/ecdsa, crypto/rsa),
// and the KMS/HSM cryptosigner bridge (cryptosigner.go) does the same
// round trip before returning. The buffer is only returned to the pool
// AFTER Sign has returned and the final token string has been copied out
// of it (buf.String() below always copies), so no concurrent issuance can
// observe or mutate it mid-flight.
func signCompactJWS(ctx context.Context, sgn jwsSigner, header, payload any, errPrefix string) (string, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	buf, _ := signingBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer signingBufPool.Put(buf)

	writeB64Segment(buf, hb)
	buf.WriteByte('.')
	writeB64Segment(buf, pb)

	sig, err := sgn.Sign(ctx, buf.Bytes())
	if err != nil {
		return "", fmt.Errorf("%s: %w", errPrefix, err)
	}

	buf.WriteByte('.')
	writeB64Segment(buf, sig)
	return buf.String(), nil
}

// writeB64Segment appends the RawURLEncoding base64 of src directly into
// buf's backing array via the Go 1.21+ AvailableBuffer idiom, avoiding the
// intermediate string base64.RawURLEncoding.EncodeToString(src) would
// otherwise allocate. Once buf's capacity has warmed up (steady state
// after the first few pool uses), this appends with zero further
// allocations.
func writeB64Segment(buf *bytes.Buffer, src []byte) {
	n := base64.RawURLEncoding.EncodedLen(len(src))
	buf.Grow(n)
	dst := buf.AvailableBuffer()[:n]
	base64.RawURLEncoding.Encode(dst, src)
	buf.Write(dst)
}

// Clock abstracts the wall-clock read every {Ed25519,ECDSA,RSA} issuer
// makes at issuance time (the iat/nbf/exp timestamps stamped into every
// minted token). Its ONLY purpose is deterministic testing — a test can
// wire a fixed or steppable Clock via With{Ed25519,ECDSA,RSA}Clock to
// assert exact claim values without sleeping or tolerating a timing
// window.
type Clock interface {
	Now() time.Time
}

// nowFrom returns c.Now(), or the real wall clock when c is nil. Every
// issuance call site uses this instead of calling time.Now() directly.
// Every issuer's zero-value clock field is nil, so an issuer built
// without a With*Clock option is byte-identical to the pre-Clock-
// injection code in every production deployment — nowFrom changes ONLY
// which clock answers Now(); claim computation (exp = now.Add(ttl),
// etc.) is unchanged.
func nowFrom(c Clock) time.Time {
	if c == nil {
		return time.Now()
	}
	return c.Now()
}
