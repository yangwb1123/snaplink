package oidc

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
	"github.com/snaplink/sso/shared/spi"
)

// UserinfoSignedAlgEdDSA is the EdDSA `userinfo_signed_response_alg`
// value — the historical default. The server honors any alg in its live
// signing-alg set (EdDSA / ES256 / RS256 / PS256), gated by
// userinfoAlgSupported so an ES256/RS256/PS256 deployment signs userinfo in
// its native alg rather than falling through to JSON; only an alg outside
// the wired set falls through.
const UserinfoSignedAlgEdDSA = "EdDSA"

// ErrUserinfoServerError is the single wire `error` value /userinfo
// returns when an opted-in encrypted response can't be produced. It is
// deliberately undifferentiated (missing RP key vs crypto failure both
// collapse here) — oracle-leak hardening per AGENTS.md §2.
const ErrUserinfoServerError = "server_error"

// UserinfoSigningDeps is what MaybeSignUserInfo needs. *sso.Server
// satisfies it via the accessor methods.
type UserinfoSigningDeps interface {
	IDTokenIssuer() IDTokenIssuer
	// IDTokenIssuerForClient selects the per-tenant issuer that should
	// sign this client's userinfo. UserinfoSigner is an optional
	// extension of IDTokenIssuer signing on the SAME key (see this
	// package's types.go), so the id_token selector also governs
	// userinfo — keeping all of a tenant's signed surfaces on one key.
	// Same fail-closed contract as IssuerForClient: emit=false ⇒ the
	// tenant strategy can't sign here (omit, never fall back to the
	// shared key); err != nil ⇒ a misconfigured/unregistered tenant
	// issuer (also omit). Returns the shared issuer for non-tenant
	// clients.
	IDTokenIssuerForClient(c *core.Client) (IDTokenIssuer, bool, error)
	ClientStoreAccessor() core.ClientStore
	SrvLogger() spi.Logger
	// SigningAlgValues is the server's live signing-alg set — the SAME
	// source the discovery doc advertises as
	// userinfo_signing_alg_values_supported. Gating signed userinfo on
	// this keeps the handler consistent with discovery: a client's
	// userinfo_signed_response_alg is honored iff the server can actually
	// produce it.
	SigningAlgValues(ctx context.Context) []string
	// JWEResponseEncrypter returns the wired response encrypter (nil
	// when none) used to encrypt the /userinfo response when the client
	// registered userinfo_encrypted_response_alg.
	JWEResponseEncrypter() security.JWEEncrypter
}

// MaybeSignUserInfo returns true when it has handled the response
// (signed JWT delivered to ctx) — callers MUST bail. False means
// the caller should fall through to the JSON response path.
//
// The signed-JWT path fires only when:
//   - clientID resolves to a registered client AND
//   - that client's UserinfoSignedResponseAlg is set AND
//   - the client's per-tenant issuer (IDTokenIssuerForClient) implements
//     UserinfoSigner
//
// The signer is resolved per-tenant so a tenant's userinfo JWT is signed
// by the SAME key as its access + id tokens. Fail-closed: a tenant whose
// strategy can't sign userinfo (emit=false, or the resolved issuer isn't
// a UserinfoSigner) is treated exactly like "no signer" — it OMITS the
// signature rather than falling back to the shared key (which would sign
// this tenant's userinfo with another key, the opposite of isolation).
//
// An alg the server can't produce (one outside its live signing-alg set)
// falls through to JSON — the spec says the AS MUST honor the request OR
// return JSON when it can't; we choose the latter to keep RPs working.
func MaybeSignUserInfo(d UserinfoSigningDeps, ctx core.HandlerContext, clientID string, body map[string]any) bool {
	clientStore := d.ClientStoreAccessor()
	if clientStore == nil || clientID == "" {
		return false
	}
	client, err := clientStore.Get(ctx.Request().Context(), clientID)
	if err != nil || client == nil {
		return false
	}

	wantSign := client.UserinfoSignedResponseAlg != ""
	wantEncrypt := client.UserinfoEncryptedResponseAlg != ""
	if !wantSign && !wantEncrypt {
		return false
	}

	// Build the inner payload. When signing is requested (and possible)
	// the JWE wraps the signed JWS; otherwise the JWE wraps the raw
	// JSON claim set. When only signing is requested, the JWS is the
	// final response.
	payload, signed, handled := signUserInfoPayload(d, ctx, client, body, wantSign, wantEncrypt)
	if handled != nil {
		// Either the signed-only sign error already wrote server_error
		// (terminal, wantEncrypt) OR the sign-only fall-through happened.
		// handled mirrors the parent's return value verbatim.
		return handled.value()
	}

	if !wantEncrypt {
		// Signed-only path.
		writeUserinfoJWT(ctx, string(payload))
		return true
	}

	return encryptUserInfoPayload(d, ctx, client, body, payload, signed)
}

// signTriState carries the three terminal outcomes of signUserInfoPayload's
// sign attempt without losing the fall-through-to-JSON (false) vs
// handled-terminal (true) boolean contract with the /userinfo caller. nil
// means "not handled — continue in the parent"; a non-nil value is the EXACT
// bool MaybeSignUserInfo must return.
type signTriState struct{ v bool }

func (s *signTriState) value() bool { return s.v }

// signUserInfoPayload runs the sign leg. It returns the inner payload, whether
// it was signed, and a non-nil handled tri-state when the parent must return
// immediately:
//   - sign error WITH wantEncrypt: writes server_error, handled=true(true) —
//     NEVER downgrade to cleartext.
//   - sign error WITHOUT wantEncrypt (sign-only): handled=true(false) — fall
//     through to JSON.
//   - unsupported alg / no signer AND no encryption: handled=true(false) —
//     fall through to JSON (the RP detects the misconfig via discovery).
//
// handled=nil means continue (encrypt path is unaffected — it keys off
// Client.JWKS, not the signer).
func signUserInfoPayload(d UserinfoSigningDeps, ctx core.HandlerContext, client *core.Client, body map[string]any, wantSign, wantEncrypt bool) ([]byte, bool, *signTriState) {
	if !wantSign {
		return nil, false, nil
	}
	reqCtx := ctx.Request().Context()
	// Resolve the signer per-tenant (UserinfoSigner extends the same
	// issuer that mints id_tokens). emit=false / a resolution error /
	// an issuer that isn't a UserinfoSigner all collapse to ok=false:
	// "can't sign here" → omit the signature, never reach for the
	// shared key. The downstream branch then either falls through to
	// JSON (sign-only) or encrypts the raw JSON under the RP's key
	// (encrypt path is unaffected — it keys off Client.JWKS, not the
	// signer).
	signer, ok := userinfoSignerForClient(d, client)
	if !ok || !userinfoSignerProducesAlg(d, ctx, signer, client.UserinfoSignedResponseAlg) {
		if !wantEncrypt {
			// Unsupported sign alg / no signer and no encryption asked —
			// fall through to JSON (the RP detects the misconfig via
			// discovery).
			return nil, false, &signTriState{false}
		}
		return nil, false, nil
	}
	jwt, serr := signer.SignUserInfo(reqCtx, client.ID, body)
	if serr != nil {
		d.SrvLogger().Error("userinfo sign failed", "error", serr, "client", client.ID)
		if wantEncrypt {
			// Opted into encryption: never downgrade to cleartext.
			writeUserinfoServerError(ctx)
			return nil, false, &signTriState{true}
		}
		return nil, false, &signTriState{false}
	}
	return []byte(jwt), true, nil
}

// encryptUserInfoPayload runs the encrypt leg and always returns true (the
// encryption path is terminal — every branch writes a response). Inner payload
// is the JWS (when signed) or the JSON claim set (when not).
func encryptUserInfoPayload(d UserinfoSigningDeps, ctx core.HandlerContext, client *core.Client, body map[string]any, payload []byte, signed bool) bool {
	reqCtx := ctx.Request().Context()
	if !signed {
		j, jerr := json.Marshal(body)
		if jerr != nil {
			d.SrvLogger().Error("userinfo marshal failed", "error", jerr, "client", client.ID)
			writeUserinfoServerError(ctx)
			return true
		}
		payload = j
	}

	enc := d.JWEResponseEncrypter()
	if enc == nil {
		// Opted-in client but no encrypter wired — fail closed.
		d.SrvLogger().Error("userinfo encryption requested but no JWEResponseEncrypter wired", "client", client.ID)
		writeUserinfoServerError(ctx)
		return true
	}
	encName := client.UserinfoEncryptedResponseEnc
	if encName == "" {
		encName = "A256GCM"
	}
	jwe, eerr := enc.Encrypt(reqCtx, payload, client.JWKS, client.UserinfoEncryptedResponseAlg, encName)
	if eerr != nil {
		// Undifferentiated: missing key + crypto failure both land here.
		d.SrvLogger().Error("userinfo encryption failed", "error", eerr, "client", client.ID)
		writeUserinfoServerError(ctx)
		return true
	}
	writeUserinfoJWT(ctx, jwe)
	return true
}

// userinfoSignerForClient resolves the UserinfoSigner that should sign
// this client's userinfo, routing through the per-tenant id_token issuer
// selector so a tenant's userinfo rides the SAME key as its access + id
// tokens. Returns ok=false (the caller omits the signature, NEVER falling
// back to the shared key) when:
//   - resolution errors (an unregistered tenant issuer — fail closed), or
//   - emit=false (the tenant strategy can't mint id_tokens, e.g. opaque
//     session tokens), or
//   - the resolved issuer doesn't implement the optional UserinfoSigner
//     extension.
//
// Crucially this does NOT consult d.IDTokenIssuer() (the shared issuer) on
// any of those paths: for a tenant client the only acceptable signer is
// that tenant's own key. Non-tenant clients get the shared issuer back
// from IDTokenIssuerForClient itself, so this is byte-identical to the
// previous `d.IDTokenIssuer().(UserinfoSigner)` for them.
// userinfoAlgSupported reports whether the client's requested
// userinfo_signed_response_alg is one this server can actually produce —
// i.e. it appears in the server's live signing-alg set (the SAME set the
// discovery doc advertises via userinfo_signing_alg_values_supported). The
// resolved per-tenant signer signs userinfo with its own key's alg; gating
// on the advertised set keeps the handler consistent with discovery, so an
// ES256 / RS256 / PS256 deployment honors the client's request instead of
// silently returning plain JSON (the prior EdDSA-only hardcode). An empty
// or unwired alg falls through to JSON unchanged.
func userinfoAlgSupported(d UserinfoSigningDeps, ctx core.HandlerContext, alg string) bool {
	if alg == "" {
		return false
	}
	for _, a := range d.SigningAlgValues(ctx.Request().Context()) {
		if a == alg {
			return true
		}
	}
	return false
}

// userinfoSignerProducesAlg reports whether the RESOLVED signer will actually
// produce the client's requested userinfo_signed_response_alg. SignUserInfo
// takes no alg parameter — the signer always signs with its own fixed key alg —
// so when the signer reports its alg (the default issuers do via Alg()) we
// require an EXACT match. Without this, a multi-alg deployment whose resolved
// per-tenant signer's alg differs from the requested alg would emit a JWT in
// the WRONG alg, breaking the client's registered contract. Signers that don't
// report an alg (third-party UserinfoSigner impls) fall back to the
// discovery-consistent server-set membership check.
func userinfoSignerProducesAlg(d UserinfoSigningDeps, ctx core.HandlerContext, signer UserinfoSigner, alg string) bool {
	if alg == "" {
		return false
	}
	if ar, ok := signer.(interface{ Alg() string }); ok {
		return ar.Alg() == alg
	}
	return userinfoAlgSupported(d, ctx, alg)
}

func userinfoSignerForClient(d UserinfoSigningDeps, client *core.Client) (UserinfoSigner, bool) {
	idIssuer, emit, err := d.IDTokenIssuerForClient(client)
	if err != nil {
		// Misconfigured/unregistered tenant issuer — fail closed by
		// omission (the access-token path surfaces the same misconfig).
		d.SrvLogger().Error("userinfo signer resolution failed; omitting signature", "error", err, "client", client.ID)
		return nil, false
	}
	if !emit || idIssuer == nil {
		return nil, false
	}
	signer, ok := idIssuer.(UserinfoSigner)
	return signer, ok
}

// writeUserinfoJWT emits a JWT/JWE userinfo response (application/jwt).
func writeUserinfoJWT(ctx core.HandlerContext, token string) {
	w := ctx.ResponseWriter()
	w.Header().Set("Content-Type", "application/jwt")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(token))
}

// writeUserinfoServerError emits the single undifferentiated
// server_error response. Carries no-store (credential endpoint) + a 500
// so RPs treat it as transient. Detail is logged, never surfaced.
func writeUserinfoServerError(ctx core.HandlerContext) {
	w := ctx.ResponseWriter()
	w.Header().Set("Cache-Control", "no-store")
	ctx.JSON(http.StatusInternalServerError, core.ErrorBody(ErrUserinfoServerError))
}
