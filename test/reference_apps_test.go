package ssotest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/protocols/oidc/browsersso"
	"github.com/yangwb1123/snaplink/shared/core"
)

func refAppFullScopes(binding refAppClient) []string { return []string{"openid", binding.Scope} }

func (h *referenceApps) login(t *testing.T, app, tenantID string, resume bool) refAppTokens {
	t.Helper()
	binding := h.clients[app+"/"+tenantID]
	return h.exchange(t, h.begin(t, binding, resume, refAppFullScopes(binding)))
}

func (h *referenceApps) refresh(t *testing.T, tokens refAppTokens) refAppTokens {
	t.Helper()
	response := h.postForm(t, core.PathToken, tokens.binding, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.refresh}})
	refAppWant(t, response, http.StatusOK, "")
	rotated := refAppTokens{binding: tokens.binding, session: tokens.session}
	rotated.access, _ = response.body[core.KeyAccessToken].(string)
	rotated.refresh, _ = response.body[core.KeyRefreshToken].(string)
	if rotated.access == "" || rotated.refresh == "" || rotated.refresh == tokens.refresh {
		t.Fatal("refresh did not issue a distinct successor")
	}
	if response.body[core.KeyIDToken] != nil {
		t.Fatal("reference refresh contract unexpectedly added an ID token")
	}
	return rotated
}

func (h *referenceApps) assertAPI(t *testing.T, tokens refAppTokens, mode string) {
	t.Helper()
	response := h.api(t, tokens.binding.App, mode, tokens.binding.Tenant, tokens.access)
	refAppWant(t, response, http.StatusOK, "")
	rows, ok := response.body["items"].([]any)
	if response.body["tenant"] != tokens.binding.Tenant || response.body["app"] != tokens.binding.App ||
		response.body["user"] != "user-"+tokens.binding.Tenant || !ok || len(rows) != 1 || rows[0] != tokens.binding.Tenant+"-"+tokens.binding.App+"-row" {
		t.Fatal("resource response escaped its application/tenant/user binding")
	}
}

func TestE2E_ReferenceAppsIndependentGrants(t *testing.T) {
	h := newReferenceApps(t)
	response, err := (&http.Client{Timeout: 5 * time.Second}).Get(h.base + "/.well-known/openid-configuration")
	discovery := refAppRead(t, response, err)
	refAppWant(t, discovery, http.StatusOK, "")
	if discovery.body["issuer"] != h.base || discovery.body["token_endpoint"] != h.base+core.PathToken || discovery.body["jwks_uri"] != h.base+core.PathJWKS {
		t.Fatal("discovery does not match the configured issuer/endpoints")
	}
	access, refresh, sessions := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for index, tenantID := range refTenantIDs {
		orders := h.login(t, "orders", tenantID, false)
		reports := h.login(t, "reports", tenantID, true)
		if h.passwordCalls.Load() != int64(index+1) {
			t.Fatal("second RP repeated password verification")
		}
		origin, _ := url.Parse(h.base)
		foundCookie := false
		for _, cookie := range h.browsers[tenantID].Jar.Cookies(origin) {
			foundCookie = foundCookie || cookie.Name == browsersso.CookieName
		}
		if !foundCookie {
			t.Fatal("browser did not retain the OP identity cookie")
		}
		a, b := h.accessClaims(t, orders), h.accessClaims(t, reports)
		if a.Raw["auth_time"] == nil || a.Raw["auth_time"] != b.Raw["auth_time"] || !slices.Contains(a.Scopes(), orders.binding.Scope) {
			t.Fatal("RP resume lost authentication context")
		}
		for _, tokens := range []refAppTokens{orders, reports} {
			claims := h.accessClaims(t, tokens)
			if claims.TenantID != tenantID || claims.ClientID != tokens.binding.ID || claims.Subject != "user-"+tenantID ||
				!slices.Equal(claims.Audience, []string{tokens.binding.Audience}) || claims.Raw["aud"] != tokens.binding.Audience ||
				claims.Raw["sid"] != tokens.session || !slices.Equal(claims.Scopes(), refAppFullScopes(tokens.binding)) || claims.JTI == "" {
				t.Fatal("access token lost client/tenant/audience/scope/session/JTI binding")
			}
			if access[tokens.access] || refresh[tokens.refresh] || sessions[tokens.session] {
				t.Fatal("RP registrations shared credentials or RP sessions")
			}
			access[tokens.access], refresh[tokens.refresh], sessions[tokens.session] = true, true, true
			for _, mode := range []string{"online", "offline"} {
				h.assertAPI(t, tokens, mode)
			}
		}
	}
}

func TestE2E_ReferenceAppsAPIIsolation(t *testing.T) {
	h := newReferenceApps(t)
	a, b := h.login(t, "orders", "tenant-a", false), h.login(t, "orders", "tenant-b", false)
	reports := h.clients["reports/tenant-a"]
	limited := h.exchange(t, h.begin(t, reports, true, []string{"openid"}))
	for _, mode := range []string{"online", "offline"} {
		for _, tc := range []struct {
			name, app, tenantID, bearer, code string
			status                            int
		}{
			{"missing", "orders", "tenant-a", "", "", 401},
			{"garbage", "orders", "tenant-a", "not.a.token", "invalid_token", 401},
			{"ID token", "orders", "tenant-a", a.id, "invalid_token", 401},
			{"other app", "reports", "tenant-a", a.access, "invalid_token", 401},
			{"other tenant", "orders", "tenant-b", a.access, core.ErrTenantMismatch, 403},
			{"other tenant reverse", "orders", "tenant-a", b.access, core.ErrTenantMismatch, 403},
			{"missing scope", "reports", "tenant-a", limited.access, "insufficient_scope", 403},
			{"forged tenant", "orders", "tenant-b", refAppForgeTenant(t, a.access), "invalid_token", 401},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				out := h.api(t, tc.app, mode, tc.tenantID, tc.bearer)
				refAppWant(t, out, tc.status, tc.code)
				if tc.status == 401 && !strings.HasPrefix(out.header.Get("WWW-Authenticate"), "Bearer") {
					t.Fatal("RS rejection omitted bearer challenge")
				}
			})
		}
	}
	if err := h.permissions.UnassignRoles(t.Context(), "user-tenant-a", a.binding.ID, []string{refAppRole}); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"online", "offline"} {
		refAppWant(t, h.api(t, "orders", mode, "tenant-a", a.access), 403, "permission_denied")
		h.assertAPI(t, b, mode)
	}
}

func refAppForgeTenant(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	claims := map[string]any{}
	if err != nil || json.Unmarshal(raw, &claims) != nil {
		t.Fatal("decode forgery fixture")
	}
	claims["tenant_id"] = "tenant-b"
	raw, err = json.Marshal(claims)
	if err != nil {
		t.Fatal("encode forgery fixture")
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(raw)
	return strings.Join(parts, ".")
}

func TestE2E_ReferenceAppsGrantIsolation(t *testing.T) {
	h := newReferenceApps(t)
	client := h.clients["orders/tenant-a"]
	grant := h.begin(t, client, false, refAppFullScopes(client))
	tokens := h.exchange(t, grant)
	unknown := h.postForm(t, core.PathToken, client, url.Values{"grant_type": {"authorization_code"}, "code": {"unknown-code"}, "redirect_uri": {client.Redirect}, "code_verifier": {refAppRandom(t)}})
	refAppWant(t, unknown, 400, "invalid_grant")
	consumed := h.postForm(t, core.PathToken, client, grant.form())
	refAppWant(t, consumed, 400, "invalid_grant")
	if !bytes.Equal(unknown.raw, consumed.raw) {
		t.Fatal("consumed/unknown code errors differ")
	}
	for _, wrongClient := range []bool{false, true} {
		fresh := h.begin(t, client, true, refAppFullScopes(client))
		form, auth := fresh.form(), client
		if wrongClient {
			auth = h.clients["reports/tenant-a"]
		} else {
			form.Set("code_verifier", refAppRandom(t))
		}
		out := h.postForm(t, core.PathToken, auth, form)
		refAppWant(t, out, 400, "invalid_grant")
		if !bytes.Equal(unknown.raw, out.raw) {
			t.Fatal("code binding failure became a credential oracle")
		}
	}
	rotated := h.refresh(t, tokens)
	before, after := h.accessClaims(t, tokens), h.accessClaims(t, rotated)
	if before.ClientID != after.ClientID || before.TenantID != after.TenantID || before.Raw["sid"] != after.Raw["sid"] || before.Raw["auth_time"] != after.Raw["auth_time"] || !slices.Equal(before.Scopes(), after.Scopes()) {
		t.Fatal("refresh changed authorization/authentication binding")
	}
	for _, mode := range []string{"online", "offline"} {
		h.assertAPI(t, rotated, mode)
	}
	for _, refreshToken := range []string{tokens.refresh, rotated.refresh, "unknown-refresh"} {
		out := h.postForm(t, core.PathToken, client, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}})
		refAppWant(t, out, 400, "invalid_grant")
		if !bytes.Equal(unknown.raw, out.raw) {
			t.Fatal("refresh reuse/family/unknown error differs from invalid_grant")
		}
	}
	other := h.login(t, "orders", "tenant-a", true)
	out := h.postForm(t, core.PathToken, h.clients["orders/tenant-b"], url.Values{"grant_type": {"refresh_token"}, "refresh_token": {other.refresh}})
	refAppWant(t, out, 400, "invalid_grant")
}

func TestE2E_ReferenceAppsRevocationModes(t *testing.T) {
	h := newReferenceApps(t)
	a, b := h.login(t, "orders", "tenant-a", false), h.login(t, "reports", "tenant-a", true)
	for _, mode := range []string{"online", "offline"} {
		h.assertAPI(t, a, mode)
	}
	for _, token := range []string{a.access, "unknown-token"} {
		refAppWant(t, h.postForm(t, core.PathRevoke, a.binding, url.Values{"token": {token}}), 200, "")
	}
	inactive := h.postForm(t, core.PathIntrospect, a.binding, url.Values{"token": {a.access}})
	refAppWant(t, inactive, 200, "")
	if len(inactive.body) != 1 || inactive.body["active"] != false {
		t.Fatal("inactive introspection leaked additional metadata")
	}
	refAppWant(t, h.api(t, "orders", "online", "tenant-a", a.access), 401, "invalid_token")
	// Offline validation intentionally cannot observe the AS deny-set.
	h.assertAPI(t, a, "offline")
	for _, mode := range []string{"online", "offline"} {
		h.assertAPI(t, b, mode)
	}
	// No automatic fallback to the offline route when the AS is unavailable.
	h.http.Close()
	refAppWant(t, h.api(t, "reports", "online", "tenant-a", b.access), 401, "invalid_token")
	h.assertAPI(t, b, "offline")
}

func TestE2E_ReferenceAppsLogout(t *testing.T) {
	h := newReferenceApps(t)
	a, b := h.login(t, "orders", "tenant-a", false), h.login(t, "reports", "tenant-a", true)
	logout := h.postJSON(t, "tenant-a", core.PathLogout, map[string]any{"session_id": a.session}, a.access)
	refAppWant(t, logout, 200, "")
	refAppWant(t, h.api(t, "orders", "online", "tenant-a", a.access), 401, "invalid_token")
	refAppWant(t, h.postForm(t, core.PathToken, a.binding, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {a.refresh}}), 400, "invalid_grant")
	for _, mode := range []string{"online", "offline"} {
		h.assertAPI(t, b, mode)
	}
	h.refresh(t, b)
	origin, _ := url.Parse(h.base)
	for _, cookie := range h.browsers["tenant-a"].Jar.Cookies(origin) {
		if cookie.Name == browsersso.CookieName {
			t.Fatal("logout retained the OP identity cookie")
		}
	}
	challenge := sha256.Sum256([]byte(refAppRandom(t)))
	resume := h.postJSON(t, "tenant-a", core.PathLogin, map[string]any{"client_id": b.binding.ID, "response_type": "code", "redirect_uri": b.binding.Redirect,
		"scope": refAppFullScopes(b.binding), "resource": []string{b.binding.Audience}, "resume_session": true,
		"code_challenge": base64.RawURLEncoding.EncodeToString(challenge[:]), "code_challenge_method": "S256"}, "")
	refAppWant(t, resume, 400, "login_required")
}

func TestE2E_ReferenceAppsSigningKeyOverlap(t *testing.T) {
	h := newReferenceApps(t)
	old := h.login(t, "orders", "tenant-a", false)
	newKid, err := h.issuer.RotateNow()
	if err != nil {
		t.Fatal("rotate reference signing key")
	}
	// Respect the consumer's existing forced-fetch debounce. Observe key
	// convergence, not a weakened refresh interval or a fixed sleep assumption.
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := h.cache.GetJWK(ctx, newKid); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("consumer did not discover the rotated verification key")
		case <-tick.C:
		}
	}
	newTokens := h.login(t, "orders", "tenant-a", true)
	if strings.Split(old.access, ".")[0] == strings.Split(newTokens.access, ".")[0] {
		t.Fatal("new access token did not use the promoted key")
	}
	for _, mode := range []string{"online", "offline"} {
		h.assertAPI(t, old, mode)
		h.assertAPI(t, newTokens, mode)
	}
}
