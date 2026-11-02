package tokengrant

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

// Boundary counters are not persistence evidence. HTTP tests use real stores.
type cibaRefreshProbe struct {
	fakeCIBAGrantDeps
	storeReads, issues, events int
	unwired                    bool
	record                     *oauth.RefreshToken
	auth                       oauth.RefreshAuthContext
	ttl                        time.Duration
	jkt                        string
	rotation                   bool
}

func (p *cibaRefreshProbe) RefreshTokenStore() oauth.RefreshTokenStore {
	p.storeReads++
	if p.unwired {
		return nil
	}
	return fakeRefreshStorePresent{}
}

func (p *cibaRefreshProbe) IssueRefreshToken(_ context.Context, userID, clientID, provider string, scopes []string, attributes map[string]string, familyID string, resources []string, details []byte, sid string, auth oauth.RefreshAuthContext, ttl time.Duration, jkt string) (string, error) {
	p.issues++
	p.record = &oauth.RefreshToken{UserID: userID, ClientID: clientID, Provider: provider,
		Scopes: scopes, Attributes: attributes, FamilyID: familyID,
		Resources: resources, AuthorizationDetails: details, SID: sid}
	p.auth, p.ttl, p.jkt = auth, ttl, jkt
	return "unit-managed-ciba-refresh", p.refreshErr
}

func (p *cibaRefreshProbe) RecordRefreshTokenIssued(_ core.HandlerContext, _, _ string, rotation bool) {
	p.events++
	p.rotation = rotation
}

type cibaRefreshGrantCase struct {
	name                        string
	grants, scopes              []string
	unwired, fail               bool
	reads, issues, events, logs int
	refresh                     bool
}

func cibaRefreshGrantCases() []cibaRefreshGrantCase {
	return []cibaRefreshGrantCase{
		{name: "nil legacy no offline", reads: 1, issues: 1, events: 1, refresh: true},
		{name: "empty legacy no offline", grants: []string{}, scopes: []string{"openid"}, reads: 1, issues: 1, events: 1, refresh: true},
		{name: "explicit permits no offline", grants: []string{core.GrantCIBA, core.GrantRefreshToken}, scopes: []string{"openid"}, reads: 1, issues: 1, events: 1, refresh: true},
		{name: "duplicate exact", grants: []string{core.GrantRefreshToken, core.GrantCIBA, core.GrantRefreshToken}, reads: 1, issues: 1, events: 1, refresh: true},
		{name: "ciba alone", grants: []string{core.GrantCIBA}},
		{name: "unrelated grant", grants: []string{core.GrantAuthorizationCode}},
		{name: "offline scope cannot override denial", grants: []string{core.GrantCIBA}, scopes: []string{"openid", core.ScopeOfflineAccess}},
		{name: "prefix alias", grants: []string{core.GrantCIBA, "xrefresh_token"}},
		{name: "suffix alias", grants: []string{core.GrantCIBA, "refresh_token:extra"}},
		{name: "case alias", grants: []string{core.GrantCIBA, "REFRESH_TOKEN"}},
		{name: "whitespace alias", grants: []string{core.GrantCIBA, "refresh_token "}},
		{name: "unsplit entry", grants: []string{core.GrantCIBA + " " + core.GrantRefreshToken}},
		{name: "empty string is explicit denial", grants: []string{""}},
		{name: "denied unwired never reads", grants: []string{core.GrantCIBA}, unwired: true},
		{name: "denied error unreachable", grants: []string{core.GrantCIBA}, fail: true},
		{name: "allowed unwired", grants: []string{core.GrantCIBA, core.GrantRefreshToken}, unwired: true, reads: 1},
		{name: "allowed store failure", grants: []string{core.GrantCIBA, core.GrantRefreshToken}, fail: true, reads: 1, issues: 1, logs: 1},
	}
}

func TestCIBARefreshGrant_Boundary(t *testing.T) {
	for _, tc := range cibaRefreshGrantCases() {
		t.Run(tc.name, func(t *testing.T) {
			p := &cibaRefreshProbe{unwired: tc.unwired}
			if tc.fail {
				p.refreshErr = errors.New("unit-ciba-store-failure")
			}
			r := &oauth.CIBARequest{SubjectID: "unit-user", Scopes: tc.scopes}
			client := &core.Client{ID: "unit-client", GrantTypes: tc.grants}
			before, _ := json.Marshal(r)
			resp := map[string]any{core.KeyAccessToken: "unit-access", core.KeyIDToken: "unit-id"}
			cibaIssueRefresh(p, newBackgroundCtx(), client, r, "unit-provider", time.Now(), "", resp)
			if p.storeReads != tc.reads || p.issues != tc.issues || p.events != tc.events || len(p.loggedErrors) != tc.logs {
				t.Fatalf("reads/issues/events/logs=%d/%d/%d/%d want=%d/%d/%d/%d", p.storeReads, p.issues, p.events, len(p.loggedErrors), tc.reads, tc.issues, tc.events, tc.logs)
			}
			_, present := resp[core.KeyRefreshToken]
			if present != tc.refresh || resp[core.KeyAccessToken] != "unit-access" || resp[core.KeyIDToken] != "unit-id" || p.rotation {
				t.Fatal("refresh presence, independent access/ID tokens or initial-event kind changed")
			}
			after, _ := json.Marshal(r)
			if string(before) != string(after) || (tc.logs != 0 && p.loggedErrors[0] != "refresh token issue failed") {
				t.Fatal("approved request or failure log changed")
			}
		})
	}
}

func TestCIBARefreshGrant_PreservesApprovedContext(t *testing.T) {
	p := &cibaRefreshProbe{}
	r := &oauth.CIBARequest{SubjectID: "unit-user", Provider: "unit-provider", Scopes: []string{"openid", "api:read"},
		Resources: []string{"unit-resource"}, ACRValues: "unit-acr", Nonce: "rp-nonce-not-a-family"}
	client := &core.Client{ID: "unit-client", GrantTypes: []string{core.GrantCIBA, core.GrantRefreshToken}, RefreshTokenTTL: 17 * time.Minute}
	now := time.Unix(1700000000, 123456789)
	resp := map[string]any{}
	cibaIssueRefresh(p, newBackgroundCtx(), client, r, r.Provider, now, "unit-dpop-jkt", resp)
	want := &oauth.RefreshToken{UserID: r.SubjectID, ClientID: client.ID, Provider: r.Provider, Scopes: r.Scopes, Resources: r.Resources}
	if !reflect.DeepEqual(p.record, want) || p.ttl != client.RefreshTokenTTL || p.jkt != "unit-dpop-jkt" || p.issues != 1 || p.events != 1 || p.rotation {
		t.Fatal("approved context, empty family/SID/details/attributes, TTL or sender constraint changed")
	}
	if !reflect.DeepEqual(p.auth, oauth.RefreshAuthContext{ACR: r.ACRValues, AuthTime: now}) {
		t.Fatal("original authentication context or zero lineage fields changed")
	}
	if &p.record.Scopes[0] != &r.Scopes[0] || &p.record.Resources[0] != &r.Resources[0] {
		t.Fatal("approved scope/resource slice aliases changed")
	}
}

type cibaRefreshIssuer struct{ fakeTokenIssuer }

func (i cibaRefreshIssuer) Issue(ctx context.Context, sub *core.Subject, scopes []string) (*core.Token, error) {
	token, err := i.fakeTokenIssuer.Issue(ctx, sub, scopes)
	if token != nil {
		token.RefreshToken = "unit-issuer-refresh-never-forwarded"
	}
	return token, err
}

func TestCIBARefreshGrant_PollPushSharedBuilder(t *testing.T) {
	for _, push := range []bool{false, true} {
		for _, allow := range []bool{false, true} {
			for _, unwired := range []bool{false, true} {
				cibaRefreshBuilderCase(t, push, allow, unwired)
			}
		}
	}
}

func cibaRefreshBuilderCase(t *testing.T, push, allow, unwired bool) {
	t.Helper()
	p := &cibaRefreshProbe{unwired: unwired, fakeCIBAGrantDeps: fakeCIBAGrantDeps{
		issuer: &cibaRefreshIssuer{}, strategy: "jwt", idTokenIssuer: fakeIDTokenIssuer{}, idTokenEmit: true}}
	client := &core.Client{ID: "rp", GrantTypes: []string{core.GrantCIBA}}
	if allow {
		client.GrantTypes = append(client.GrantTypes, core.GrantRefreshToken)
	}
	r := approvedCIBARequest()
	var raw []byte
	var present, ok bool
	if push {
		var payload oauth.PushPayload
		payload, ok = MintCIBATokensForPush(p, newBackgroundCtx(), client, r, time.Now())
		raw, _ = json.Marshal(payload)
	} else {
		var body map[string]any
		body, ok = buildCIBATokenResponse(p, newBackgroundCtx(), client, r, time.Now(), "", "")
		raw, _ = json.Marshal(body)
	}
	var response map[string]any
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	_, present = response[core.KeyRefreshToken]
	if !ok || present != (allow && !unwired) || response[core.KeyAccessToken] != "AT-user-1" || response[core.KeyIDToken] != "IDT-user-1" {
		t.Fatalf("poll/push independence changed: push=%v allow=%v unwired=%v", push, allow, unwired)
	}
	want := 0
	if allow && !unwired {
		want = 1
	}
	if p.issues != want || p.events != want || p.rotation || (present && response[core.KeyRefreshToken] != "unit-managed-ciba-refresh") {
		t.Fatal("shared builder bypassed managed grant policy or forwarded issuer refresh")
	}
}
