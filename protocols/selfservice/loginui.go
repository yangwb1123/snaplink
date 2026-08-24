package selfservice

import (
	"encoding/json"
	"mime"
	"net/http"
	"regexp"
	"strings"

	"github.com/yangwb1123/snaplink/interfaces/middleware"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

// HandleLoginUIMetadata serves GET /api/v1/login-ui/metadata?client_id=...
// Returns endpoints, issuer, and client info for custom login UI facades.
// The caller (Server handler wrapper) enriches the response with geo and
// provider data via ctx.Set values.
func HandleLoginUIMetadata(d Deps, ctx core.HandlerContext) {
	clientID := ctx.Query("client_id")
	if clientID == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	iss := d.ResolveIssuer(ctx)
	meta := map[string]any{
		"client_id": clientID,
		"iss":       iss,
		"endpoints": map[string]string{
			"authorization": iss + "/auth/login",
			"token":         iss + "/token",
			"userinfo":      iss + "/userinfo",
			"jwks":          iss + "/.well-known/jwks.json",
		},
	}
	// Pass through any caller-enriched data from context.
	if v := ctx.Get("extensions"); v != nil {
		meta["extensions"] = v
	}
	d.TokenNoStoreHeaders(ctx)
	ctx.JSON(http.StatusOK, meta)
}

// preferenceValidators allowlists the keys a bearer may read/write via
// /me/preferences. DEFAULT-DENY: User.Attributes is a shared bag that also
// carries credential material (password_hash*, seeded_password, scim:* and
// backend internals) — only keys with an explicit validator may be surfaced
// or mutated through the self-service endpoint.
var preferenceValidators = map[string]func(string) bool{
	"locale": func(v string) bool {
		// BCP47 language tag: zh-CN / en-US / zh-Hans-CN ...
		if len(v) > 32 {
			return false
		}
		ok, _ := regexp.MatchString(`^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$`, v)
		return ok
	},
	"zoneinfo": func(v string) bool {
		// IANA time-zone name (Asia/Shanghai, UTC ...). Loose validation:
		// non-empty, printable ASCII, <=64 chars, no control characters.
		if len(v) == 0 || len(v) > 64 {
			return false
		}
		for _, r := range v {
			if r < 0x20 || r > 0x7e {
				return false
			}
		}
		return true
	},
	"sverp:theme_mode": func(v string) bool {
		switch v {
		case "light", "dark", "auto":
			return true
		}
		return false
	},
}

// preferenceOrder keeps GET responses deterministic.
var preferenceOrder = []string{"locale", "zoneinfo", "sverp:theme_mode"}

// HandleMyPreferencesGet serves GET /me/preferences — the bearer's
// allowlisted preferences (locale / zoneinfo / sverp:theme_mode) from
// User.Attributes. Absent keys are omitted; unknown/unreleasable keys are
// never returned (default-deny, see preferenceValidators).
func HandleMyPreferencesGet(d Deps, ctx core.HandlerContext, userID string) {
	middleware.TokenNoStoreHeaders(ctx)
	rctx := ctx.Request().Context()
	user, err := d.UserProvider().GetByID(rctx, userID)
	if err != nil || user == nil {
		d.Logger().Error("preferences: user lookup failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	out := make(map[string]string, len(preferenceOrder))
	for _, key := range preferenceOrder {
		if _, release := preferenceValidators[key]; !release {
			continue
		}
		if v := user.Attributes[key]; v != "" && preferenceValidators[key](v) {
			out[key] = v
		}
	}
	ctx.JSON(http.StatusOK, out)
}

// HandleMyPreferencesPut serves PUT /me/preferences — merges allowlisted
// preference keys into the bearer's attributes. Body:
//
//	{"locale": "zh-CN", "sverp:theme_mode": "dark"}
//
// Unknown keys are rejected with 400 (fail-closed: a typo must not silently
// write a stray attribute). Values are validated per-key. A key explicitly
// set to "" is removed.
func HandleMyPreferencesPut(d Deps, ctx core.HandlerContext, userID string) {
	middleware.TokenNoStoreHeaders(ctx)
	req, ok := bindPreferenceRequest(ctx)
	if !ok {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}

	rctx := ctx.Request().Context()
	user, err := d.UserProvider().GetByID(rctx, userID)
	if err != nil || user == nil {
		d.Logger().Error("preferences: user lookup failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	if !mergePreferences(user, req) {
		ctx.JSON(http.StatusOK, map[string]any{"status": "ok"})
		return
	}
	if err := d.UserProvider().CreateOrUpdate(rctx, user); err != nil {
		d.Logger().Error("preferences: persist failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	if d.Auditor() != nil {
		evt := &audit.Event{Type: audit.EventUserPrefsUpdated, Outcome: audit.OutcomeSuccess, ActorID: userID, ActorIP: audit.ClientIP(ctx.Request())}
		d.Auditor().Record(rctx, evt)
	}
	ctx.JSON(http.StatusOK, map[string]any{"status": "ok"})
}

func bindPreferenceRequest(ctx core.HandlerContext) (map[string]string, bool) {
	mediaType, _, err := mime.ParseMediaType(ctx.Request().Header.Get(core.HeaderContentType))
	if err != nil || !strings.EqualFold(mediaType, core.ContentTypeJSON) {
		return nil, false
	}
	var raw map[string]json.RawMessage
	if oauth.BindParams(ctx, &raw) != nil || raw == nil || len(raw) > len(preferenceValidators) {
		return nil, false
	}
	req := make(map[string]string, len(raw))
	for key, value := range raw {
		var text *string
		if err := json.Unmarshal(value, &text); err != nil || text == nil {
			return nil, false
		}
		req[key] = *text
	}
	if !validPreferenceRequest(req) {
		return nil, false
	}
	return req, true
}

func validPreferenceRequest(req map[string]string) bool {
	if len(req) > len(preferenceValidators) {
		return false
	}
	for key, value := range req {
		validate, allowlisted := preferenceValidators[key]
		if !allowlisted || value != "" && !validate(value) {
			return false
		}
	}
	return true
}

func mergePreferences(user *core.User, req map[string]string) bool {
	if user.Attributes == nil {
		user.Attributes = make(map[string]string, len(req))
	}
	changed := false
	for key, value := range req {
		value = strings.TrimSpace(value)
		current := user.Attributes[key]
		if value == "" {
			if current != "" {
				delete(user.Attributes, key)
				changed = true
			}
			continue
		}
		if current != value {
			user.Attributes[key] = value
			changed = true
		}
	}
	return changed
}
