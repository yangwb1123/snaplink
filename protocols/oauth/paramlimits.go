package oauth

import (
	"errors"
	"net/http"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

// Authorize request parameter length limits — hard caps that prevent
// a single large parameter (state, scope, redirect_uri, nonce) from
// consuming excessive memory or storage in PAR / AuthCode stores.
//
// Applied in [ValidateAuthRequestParams] after the request is bound
// but before it is persisted. Values exceeding these limits receive
// a 400 invalid_request response.
const (
	MaxStateLen       = 2048 // bytes — RFC 6749 recommends >= 128 bits
	MaxRedirectURILen = 2048 // bytes — no RFC max; 2 KB is generous
	MaxScopeLen       = 4096 // bytes — 100 scopes × 40 chars on average
	MaxNonceLen       = 256  // bytes — OIDC nonce, typically 16-32 bytes
	MaxResourceLen    = 2048 // bytes — per RFC 8707 resource indicator
	MaxCustomParamLen = 4096 // bytes — any other auth request parameter
)

// ValidateAuthRequestParamLength checks individual OAuth authorization
// request parameters against their maximum allowed length. Returns a
// non-nil error code when a parameter exceeds its limit.
//
// This is a safety net — not a replacement for proper parameter
// validation. It runs AFTER the request is bound and BEFORE it is
// persisted to PAR/AuthCode stores.
func ValidateAuthRequestParamLength(key, value string) string {
	if value == "" {
		return ""
	}
	switch key {
	case "state":
		if len(value) > MaxStateLen {
			return core.ErrInvalidRequest
		}
	case "redirect_uri":
		if len(value) > MaxRedirectURILen {
			return core.ErrInvalidRequest
		}
	case "scope":
		if len(value) > MaxScopeLen {
			return core.ErrInvalidRequest
		}
	case "nonce":
		if len(value) > MaxNonceLen {
			return core.ErrInvalidRequest
		}
	case "resource":
		if len(value) > MaxResourceLen {
			return core.ErrInvalidRequest
		}
	default:
		if len(value) > MaxCustomParamLen {
			return core.ErrInvalidRequest
		}
	}
	return ""
}

// CheckAuthParamLengths validates the standard authorization request
// parameters against their maximum allowed lengths. Returns the first
// error code encountered (always ErrInvalidRequest), or "" when all
// parameters are within limits.
//
// This is a convenience wrapper around [ValidateAuthRequestParamLength]
// for the common set of parameters present in both PAR and /auth/login
// requests. Scope is the space-separated scope string (not the split
// slice — the wire format length is what matters).
func CheckAuthParamLengths(state, redirectURI, scope, nonce string, resources []string) string {
	for _, kv := range []struct{ k, v string }{
		{"state", state},
		{"redirect_uri", redirectURI},
		{"scope", scope},
		{"nonce", nonce},
	} {
		if code := ValidateAuthRequestParamLength(kv.k, kv.v); code != "" {
			return code
		}
	}
	for _, r := range resources {
		if code := ValidateAuthRequestParamLength("resource", r); code != "" {
			return code
		}
	}
	return ""
}

func validateCIBARequestShape(d CIBADeps, ctx core.HandlerContext, req *cibaRequest) bool {
	hints := 0
	for _, hint := range []string{req.LoginHint, req.IDTokenHint, req.LoginHintToken} {
		if hint != "" {
			hints++
		}
	}
	if hints > 1 || (req.RequestedExpiry != nil && *req.RequestedExpiry <= 0) {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return false
	}
	if req.UserCode != "" && d.CIBAUserCodeVerifier() == nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return false
	}
	return true
}

func verifyCIBAUserCode(d CIBADeps, ctx core.HandlerContext, clientID, subjectID, userCode string) bool {
	verifier := d.CIBAUserCodeVerifier()
	if verifier == nil {
		return true
	}
	err := verifier.VerifyCIBAUserCode(ctx.Request().Context(), clientID, subjectID, userCode)
	switch {
	case err == nil:
		return true
	case errors.Is(err, ErrCIBAUserCodeRequired):
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrMissingUserCode))
	case errors.Is(err, ErrCIBAUserCodeInvalid):
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidUserCode))
	default:
		// A custom verifier error might accidentally contain the submitted
		// secret. Keep the wire response and logs constant; the verifier owns
		// its internal diagnostics.
		d.SrvLogger().Error("ciba user-code verifier unavailable", "client_id", clientID)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
	}
	return false
}

func effectiveCIBARequestTTL(configured time.Duration, requested *int) time.Duration {
	if configured <= 0 {
		configured = DefaultCIBARequestTTL
	}
	if requested == nil {
		return configured
	}
	seconds := int64(*requested)
	if seconds > (1<<63-1)/int64(time.Second) {
		return configured
	}
	wanted := time.Duration(seconds) * time.Second
	if wanted < configured {
		return wanted
	}
	return configured
}
