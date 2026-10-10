// Package browsersso restores authentication, never an RP's authorization.
package browsersso

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

const (
	CookieName     = "snaplink_op_session"
	cookieTTL      = 8 * time.Hour
	cookieAudience = "urn:snaplink:browser-op-session"
	cookiePurpose  = "browser-op-session"
	KeySupported   = "op_session_supported"
	KeyAvailable   = "op_session_available"
	KeyError       = "op_session_error"
	contextResult  = "snaplink.browser-op-result"
)

// Signer signs a purpose-bound identity cookie with the OP's rotating keys.
// It is not an access token or an RP's id_token_hint.
type Signer interface {
	SignJWT(context.Context, string, any) (string, error)
}

// Verifier accepts ONLY the OP-cookie JOSE typ. The generic token verifier
// must reject it before signature verification, even with the same OP keys.
type Verifier interface {
	ValidateBrowserSession(context.Context, string) (*core.TokenClaims, error)
}

type Session struct {
	signer   Signer
	verifier Verifier
}

func New(signer Signer, verifier Verifier) *Session {
	if signer == nil || verifier == nil {
		return nil
	}
	return &Session{signer: signer, verifier: verifier}
}

// Resolve checks both the signed authentication context and canonical live
// session. Revoked/expired cookies are indistinguishable from absent cookies;
// storage failures remain unavailable, not evidence of being logged out.
func (s *Session) Resolve(ctx context.Context, r *http.Request, mgr core.SessionManager, issuer string) (*core.AuthResult, error) {
	cookie, err := r.Cookie(CookieName)
	if err != nil || mgr == nil {
		return nil, nil
	}
	claims, err := s.verifier.ValidateBrowserSession(ctx, cookie.Value)
	if err != nil {
		if errors.Is(err, core.ErrTokenValidationRejected) {
			return nil, nil
		}
		return nil, err
	}
	if !validClaims(claims, issuer) {
		return nil, nil
	}
	live, err := mgr.Get(ctx, claims.SID)
	if err != nil {
		// Managers differ on missing-session sentinels. An explicit missing
		// record is a login miss; all other errors fail closed as unavailable.
		if errors.Is(err, core.ErrSessionNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if live == nil || live.Revoked || live.IsExpired() || live.StepUpRequired || live.UserID != claims.Subject {
		return nil, nil
	}
	return &core.AuthResult{
		UserID: claims.Subject, Provider: claims.Extra["provider"],
		AuthTime: claims.AuthTime, AuthMethods: append([]string(nil), claims.AMR...),
		AchievedACR: claims.ACR, CreateSession: true,
	}, nil
}

func validClaims(c *core.TokenClaims, issuer string) bool {
	return c != nil && c.TokenUse == core.TokenUseBrowserSession && c.Issuer == issuer &&
		len(c.Audience) == 1 && c.Audience[0] == cookieAudience &&
		c.Extra["purpose"] == cookiePurpose && c.Extra["provider"] != "" &&
		c.Subject != "" && c.SID != "" && !c.AuthTime.IsZero() &&
		!c.AuthTime.After(time.Now()) && c.ExpiresAt.After(time.Now())
}

// Allows never overrides a forced authentication or account-selection request.
func Allows(prompt string, maxAge *int64, authTime time.Time) bool {
	values := strings.Fields(prompt)
	if slices.Contains(values, "login") || slices.Contains(values, "select_account") ||
		(slices.Contains(values, "none") && len(values) != 1) {
		return false
	}
	return maxAge == nil || (*maxAge > 0 && time.Since(authTime).Seconds() <= float64(*maxAge))
}

func SaveResult(ctx core.HandlerContext, result *core.AuthResult) { ctx.Set(contextResult, result) }

func Result(ctx core.HandlerContext) *core.AuthResult {
	result, _ := ctx.Get(contextResult).(*core.AuthResult)
	return result
}

// Issue only follows terminal fresh authentication + application authorization.
// Its expiry is bounded by the original authentication and canonical session;
// resuming another RP never rolls the cookie's authentication age forward.
func (s *Session) Issue(ctx core.HandlerContext, live *core.Session, result *core.AuthResult, issuer string) error {
	if result == nil || live == nil || live.Revoked || live.IsExpired() || live.UserID != result.UserID {
		return core.ErrSessionNotFound
	}
	authTime := result.AuthTime
	if authTime.IsZero() {
		authTime = live.AuthTime
	}
	if authTime.IsZero() {
		authTime = live.CreatedAt
	}
	expires := authTime.Add(cookieTTL)
	if live.ExpiresAt.Before(expires) {
		expires = live.ExpiresAt
	}
	if !expires.After(time.Now()) {
		return core.ErrSessionNotFound
	}
	value, err := s.signer.SignJWT(ctx.Request().Context(), core.JWTTypBrowserSession, map[string]any{
		"iss": issuer, "aud": cookieAudience, "sub": result.UserID,
		"sid": live.ID, "iat": time.Now().Unix(), "exp": expires.Unix(),
		"auth_time": authTime.Unix(), "amr": result.AuthMethods, "acr": result.AchievedACR,
		"ext": map[string]string{"purpose": cookiePurpose, "provider": result.Provider},
	})
	if err != nil {
		return err
	}
	http.SetCookie(ctx.ResponseWriter(), cookie(value, issuer, int(time.Until(expires).Seconds())))
	return nil
}

// Clear destroys the cookie's canonical anchor as well as clearing the browser
// handle. It does not substitute a cookie for the RP logout request validation.
func (s *Session) Clear(ctx core.HandlerContext, mgr core.SessionManager, issuer string) {
	if c, err := ctx.Request().Cookie(CookieName); err == nil && mgr != nil {
		claims, verr := s.verifier.ValidateBrowserSession(ctx.Request().Context(), c.Value)
		if verr == nil && validClaims(claims, issuer) {
			_ = mgr.Destroy(ctx.Request().Context(), claims.SID)
		}
	}
	s.Expire(ctx, issuer)
}

// Expire clears only the browser handle. A failed fresh-cookie issue must not
// leave a previous account selected, nor revoke unrelated RP authorization.
func (s *Session) Expire(ctx core.HandlerContext, issuer string) {
	http.SetCookie(ctx.ResponseWriter(), cookie("", issuer, -1))
}

func cookie(value, issuer string, maxAge int) *http.Cookie {
	origin, _ := url.Parse(issuer)
	return &http.Cookie{
		Name: CookieName, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: origin != nil && origin.Scheme == "https",
		SameSite: http.SameSiteLaxMode,
	}
}
