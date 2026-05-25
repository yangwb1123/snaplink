package oidc

import (
	"encoding/json"
	"net/http"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/security"
	"github.com/snaplink/sso/spi"
)

// UserinfoSignedAlgEdDSA is the only `userinfo_signed_response_alg`
// value this server can satisfy today — matches the access-token /
// id-token signing algorithm. Other alg values fall through to JSON.
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
	ClientStoreAccessor() core.ClientStore
	SrvLogger() spi.Logger
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
//   - the wired IDTokenIssuer implements UserinfoSigner
//
// Unsupported alg values (anything besides EdDSA) fall through to
// JSON — the spec says the AS MUST honor the request OR return JSON
// when it can't; we choose the latter to keep RPs working.
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

	reqCtx := ctx.Request().Context()

	// Build the inner payload. When signing is requested (and possible)
	// the JWE wraps the signed JWS; otherwise the JWE wraps the raw
	// JSON claim set. When only signing is requested, the JWS is the
	// final response.
	var payload []byte
	signed := false
	if wantSign {
		signer, ok := d.IDTokenIssuer().(UserinfoSigner)
		if ok && client.UserinfoSignedResponseAlg == UserinfoSignedAlgEdDSA {
			jwt, serr := signer.SignUserInfo(reqCtx, client.ID, body)
			if serr != nil {
				d.SrvLogger().Error("userinfo sign failed", "error", serr, "client", client.ID)
				if wantEncrypt {
					// Opted into encryption: never downgrade to cleartext.
					writeUserinfoServerError(ctx)
					return true
				}
				return false
			}
			payload = []byte(jwt)
			signed = true
		} else if !wantEncrypt {
			// Unsupported sign alg / no signer and no encryption asked —
			// fall through to JSON (the RP detects the misconfig via
			// discovery).
			return false
		}
	}

	if !wantEncrypt {
		// Signed-only path.
		writeUserinfoJWT(ctx, string(payload))
		return true
	}

	// Encryption requested. Inner payload is the JWS (when signed) or
	// the JSON claim set (when not).
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
