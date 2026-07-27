package sso

import (
	"sync"

	"github.com/yangwb1123/snaplink/internal/auth/login"
	"github.com/yangwb1123/snaplink/platform/audit"
)

// respFieldDeviceToken is the /auth/mfa success-response field carrying a
// freshly minted "remember this device" grant. Matches the field name
// POST /me/devices/trust already returns (protocols/selfservice/
// selfserviceaccount/trusted_devices.go's response map) so client code has
// ONE field name to look for across both endpoints.
const respFieldDeviceToken = "device_token"

// finishLoginWithDeviceTrust wraps finishLogin for the MFA-resume path only:
// when the caller asked to remember this device (trust_device=true) and a
// TrustedDeviceStore is wired, it arranges for a trust grant to be minted
// LAZILY — only if finishLogin's shared response pipeline actually reaches
// its terminal 2xx write (see mfaTrustDeviceCtx below). That means a device
// is trusted only when the login succeeds end-to-end (tokens minted), never
// on a downstream failure inside finishLogin (session-store outage,
// max-active-sessions, …) even though the MFA factor itself already
// verified. trustDevice=false or no store wired is a byte-identical no-op:
// finishLogin runs exactly as it did before this feature existed, and the
// non-MFA /auth/login path (which never calls this wrapper) is untouched.
func (s *Server) finishLoginWithDeviceTrust(ctx HandlerContext, result *AuthResult, req login.Request, client *Client, subjectID string, trustDevice bool) {
	if !trustDevice || s.trustedDeviceStore == nil {
		s.finishLogin(ctx, result, req, client)
		return
	}
	s.finishLogin(s.wrapForDeviceTrust(ctx, subjectID, client.ID), result, req, client)
}

// wrapForDeviceTrust returns a HandlerContext that mints a trusted-device
// grant for (subjectID, clientID) — the SAME core.TrustedDeviceStore.Trust
// call HandleTrustMyDevice makes (protocols/selfservice/selfserviceaccount/
// trusted_devices.go) — lazily and at most once, only if finishLogin goes on
// to write a genuine 2xx success body. A Trust error is logged and otherwise
// swallowed: the user already proved their MFA factor, so failing to
// remember the device degrades UX only, never the login itself (fail-open
// on a best-effort side effect, same philosophy as AGENTS.md's Fail Modes
// table even though TrustedDeviceStore isn't literally listed there).
func (s *Server) wrapForDeviceTrust(ctx HandlerContext, subjectID, clientID string) HandlerContext {
	return &mfaTrustDeviceCtx{
		HandlerContext: ctx,
		mint: func() (string, bool) {
			token, device, err := s.trustedDeviceStore.Trust(ctx.Request().Context(), subjectID, clientID, "", s.TrustedDeviceTTL())
			if err != nil {
				s.logger.Error("mfa: trust device failed", "error", err, "user", subjectID, "client", clientID)
				return "", false
			}
			s.recordMFADeviceTrusted(ctx, subjectID, clientID, device.ID)
			return token, true
		},
	}
}

// mfaTrustDeviceCtx overrides HandlerContext.JSON to inject the minted
// device_token into finishLogin's terminal response body, without changing
// finishLogin's signature or touching any file outside this one — it only
// shadows JSON for the ONE call finishLogin makes while handling this
// request. mint runs at most once (sync.Once): only a 2xx map[string]any
// body triggers it, so every error path (any non-2xx status, or a body that
// isn't a map — e.g. the form_post / JARM authorization_code render modes,
// which never call ctx.JSON at all) passes through byte-identical to the
// unwrapped ctx, and no orphan grant is ever minted without also being
// returned to the caller in that same response.
type mfaTrustDeviceCtx struct {
	HandlerContext
	once  sync.Once
	token string
	ok    bool
	mint  func() (string, bool)
}

func (c *mfaTrustDeviceCtx) JSON(code int, v any) {
	if code >= 200 && code < 300 {
		if body, isMap := v.(map[string]any); isMap {
			c.once.Do(func() { c.token, c.ok = c.mint() })
			if c.ok {
				body[respFieldDeviceToken] = c.token
			}
		}
	}
	c.HandlerContext.JSON(code, v)
}

// recordMFADeviceTrusted mirrors selfserviceaccount.recordDeviceTrusted's
// audit shape (same event type, outcome, and device_id meta key) so a SIEM
// query for EventDeviceTrusted sees one consistent event regardless of which
// of the two entry points — self-service POST /me/devices/trust, or this
// MFA-step checkbox — minted the grant. Never records the token or its
// hash, matching the self-service handler's same invariant.
func (s *Server) recordMFADeviceTrusted(ctx HandlerContext, userID, clientID, deviceID string) {
	if s.auditor == nil {
		return
	}
	evt := &audit.Event{
		Type:     audit.EventDeviceTrusted,
		Outcome:  audit.OutcomeSuccess,
		ActorID:  userID,
		ClientID: clientID,
		ActorIP:  audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, "device_id", deviceID)
	s.auditor.Record(ctx.Request().Context(), evt)
}
