package oauth

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/shared/core"
)

// Counters observe handler seams; these are not durable-storage evidence.
type backchannelAdmissionProbe struct {
	*cibaDeps
	storeReads, hints, codes, deliveries, audits int
}

func (d *backchannelAdmissionProbe) CIBAStore() CIBAStore {
	d.storeReads++
	return d.store
}

func (d *backchannelAdmissionProbe) ResolveCIBAHint(ctx context.Context, lh, ith, lht string) (string, string, error) {
	d.hints++
	return d.cibaDeps.ResolveCIBAHint(ctx, lh, ith, lht)
}

func (d *backchannelAdmissionProbe) RecordCIBAAuthRequest(core.HandlerContext, string, string, string) {
	d.audits++
}

type backchannelAdmissionCase struct {
	name, auth, shape string
	grants            []string
	status            int
	code              string
}

func backchannelAdmissionCases() []backchannelAdmissionCase {
	deny := []string{core.GrantRefreshToken}
	return []backchannelAdmissionCase{
		{name: "nil legacy", status: 200},
		{name: "empty legacy", grants: []string{}, status: 200},
		{name: "exact", grants: []string{GrantCIBA}, status: 200},
		{name: "with refresh", grants: []string{GrantCIBA, core.GrantRefreshToken}, status: 200},
		{name: "duplicate exact", grants: []string{GrantCIBA, GrantCIBA}, status: 200},
		{name: "authorization code only", grants: []string{core.GrantAuthorizationCode}},
		{name: "refresh only", grants: deny},
		{name: "client credentials only", grants: []string{core.GrantClientCredentials}},
		{name: "blank entry", grants: []string{""}},
		{name: "prefix alias", grants: []string{"x" + GrantCIBA}},
		{name: "suffix alias", grants: []string{GrantCIBA + ":extra"}},
		{name: "case alias", grants: []string{strings.ToUpper(GrantCIBA)}},
		{name: "unsplit grants", grants: []string{GrantCIBA + " " + core.GrantRefreshToken}},
		{name: "offline scope cannot authorize", grants: deny, shape: "offline"},
		{name: "denied before missing hint", grants: deny, shape: "missing hint"},
		{name: "denied before unknown hint", grants: deny, shape: "unknown hint"},
		{name: "denied before shape validation", grants: deny, shape: "two hints"},
		{name: "denied before store error", grants: deny, shape: "store error"},
		{name: "basic overrides bad body", auth: "basic", grants: []string{GrantCIBA}, status: 200},
		{name: "basic identity still denied", auth: "basic", grants: deny},
		{name: "public permitted", auth: "public", grants: []string{GrantCIBA}, status: 200},
		{name: "public still denied", auth: "public", grants: deny},
		{name: "assertion permitted", auth: "assertion", grants: []string{GrantCIBA}, status: 200},
		{name: "assertion identity still denied", auth: "assertion", grants: deny},
		{name: "bad secret precedes authorization", auth: "bad secret", grants: deny, status: 401, code: core.ErrInvalidClient},
		{name: "unknown client precedes authorization", auth: "unknown client", grants: deny, status: 401, code: core.ErrInvalidClient},
		{name: "inactive precedes authorization", auth: "inactive", grants: deny, status: 403, code: core.ErrInactiveClient},
		{name: "tenant precedes authorization", auth: "tenant mismatch", grants: deny, status: 403, code: core.ErrTenantMismatch},
		{name: "resource precedes authorization", grants: deny, shape: "bad resource", status: 400, code: core.ErrInvalidTarget},
	}
}

func newBackchannelAdmissionProbe(tc backchannelAdmissionCase) (*backchannelAdmissionProbe, *memCIBAStore, url.Values) {
	clients, store := newMemClientStore(), newMemCIBAStore()
	client := activeClient("rp")
	client.GrantTypes, client.AllowedScopes = tc.grants, []string{"profile", "openid", "offline_access"}
	client.AllowedResources = []string{"https://s37.invalid/resource"}
	if tc.auth == "public" {
		client.TokenEndpointAuthMethod = "none"
	}
	if tc.auth == "inactive" {
		client.Active = false
	}
	if tc.auth == "tenant mismatch" {
		client.TenantID = "client-tenant"
	}
	clients.put(client, "s")
	d := &backchannelAdmissionProbe{cibaDeps: newCIBADeps(clients, store)}
	d.userCode = CIBAUserCodeVerifierFunc(func(context.Context, string, string, string) error { d.codes++; return nil })
	d.deliver = func(context.Context, string, string, string) error { d.deliveries++; return nil }
	d.verifyCA = func(context.Context, string, string, string) (string, error) { return "rp", nil }
	body := url.Values{"client_id": {"rp"}, "client_secret": {"s"}, "login_hint": {"known@user"}, "scope": {"profile"}, "user_code": {"synthetic-code"}}
	return d, store, body
}

func (tc backchannelAdmissionCase) apply(d *backchannelAdmissionProbe, store *memCIBAStore, body url.Values) {
	switch tc.auth {
	case "basic":
		body.Set("client_id", "wrong-body-client")
		body.Set("client_secret", "wrong-body-secret")
	case "public":
		body.Del("client_secret")
	case "assertion":
		body.Set("client_secret", "wrong")
		body.Set("client_assertion", "synthetic-verified-seam")
		body.Set("client_assertion_type", ClientAssertionTypeJWTBearer)
	case "bad secret":
		body.Set("client_secret", "wrong")
	case "unknown client":
		body.Set("client_id", "unknown")
	}
	switch tc.shape {
	case "offline":
		body.Set("scope", "openid offline_access")
	case "missing hint":
		body.Del("login_hint")
	case "unknown hint":
		body.Set("login_hint", "unknown")
	case "two hints":
		body.Set("id_token_hint", "synthetic-second-hint")
	case "store error":
		store.issErr = ErrCIBARequestInvalid
	case "bad resource":
		body.Set("resource", "https://other.invalid")
	}
}

func TestBackchannelGrantAdmission_Boundary(t *testing.T) {
	for _, tc := range backchannelAdmissionCases() {
		t.Run(tc.name, func(t *testing.T) {
			d, store, body := newBackchannelAdmissionProbe(tc)
			tc.apply(d, store, body)
			ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded, body.Encode())
			if tc.auth == "basic" {
				ctx.Request().SetBasicAuth("rp", "s")
			}
			if tc.auth == "tenant mismatch" {
				ctx.Set(tenant.HandlerContextKey, &tenant.Resolved{Tenant: &tenant.Tenant{ID: "other-tenant"}})
			}
			HandleBackchannelAuth(d, ctx)
			status, code := tc.status, tc.code
			if status == 0 {
				status, code = http.StatusBadRequest, core.ErrUnauthorizedClient
			}
			out := decodeBody(t, rec)
			if rec.Code != status || (code != "" && out["error"] != code) {
				t.Errorf("status/error = %d/%v, want %d/%s", rec.Code, out["error"], status, code)
			}
			if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" {
				t.Error("credential cache headers changed")
			}
			want := 0
			if status == http.StatusOK {
				want = 1
			}
			if d.hints != want || d.codes != want || d.deliveries != want || d.audits != want || len(store.entries) != want || d.storeReads != 1+want {
				t.Errorf("unexpected hint/verifier/delivery/audit/entry/store-read side effects: %d/%d/%d/%d/%d/%d", d.hints, d.codes, d.deliveries, d.audits, len(store.entries), d.storeReads)
			}
			_, pending := out["auth_req_id"]
			if pending != (want == 1) || out["access_token"] != nil || out["refresh_token"] != nil || out["id_token"] != nil {
				t.Error("denial leaked pending/credential fields, or success lost pending id")
			}
		})
	}
}

func TestBackchannelGrantAdmission_PreservesStoredContext(t *testing.T) {
	d, store, body := newBackchannelAdmissionProbe(backchannelAdmissionCase{grants: []string{GrantCIBA}})
	d.ttl, d.interval = 30*time.Second, 3*time.Second
	body.Set("scope", "profile openid profile")
	body.Set("resource", "https://s37.invalid/resource")
	body.Set("binding_message", "original-binding")
	body.Set("nonce", "original-nonce")
	body.Set("acr_values", "urn:s37:acr")
	body.Set("requested_expiry", "10")
	body.Set("client_notification_token", "synthetic-notification")
	ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded, body.Encode())
	HandleBackchannelAuth(d, ctx)
	out := decodeBody(t, rec)
	id, _ := out["auth_req_id"].(string)
	if rec.Code != http.StatusOK || id == "" {
		t.Fatal("authorized admission failed")
	}
	r, err := store.Get(t.Context(), id)
	if err != nil || r.ClientID != "rp" || r.SubjectID != "user-1" || r.Provider != "password" || r.Status != CIBAPending || !reflect.DeepEqual(r.Scopes, []string{"profile", "openid"}) || !reflect.DeepEqual(r.Resources, []string{"https://s37.invalid/resource"}) || r.BindingMessage != "original-binding" || r.Nonce != "original-nonce" || r.ACRValues != "urn:s37:acr" || r.ClientNotificationToken != "synthetic-notification" || r.Interval != 3*time.Second || r.ExpiresAt.Sub(r.CreatedAt) != 10*time.Second || out["expires_in"] != float64(10) || out["interval"] != float64(3) {
		t.Fatal("approved pending context, order/deduplication or server TTL ceiling changed")
	}
}
