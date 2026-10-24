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
	"github.com/yangwb1123/snaplink/shared/spi"
)

// These counters measure the helper boundary, not durable persistence.
// Separate HTTP tests use real memory/SQLite stores; stock acceptance uses PG.
type authCodeRefreshProbe struct {
	AuthCodeGrantDeps
	reads, issues, events int
	unwired               bool
	issueErr              error
	logs                  []string
	record                *oauth.RefreshToken
	auth                  oauth.RefreshAuthContext
	ttl                   time.Duration
	jkt                   string
	rotation              bool
}

func (p *authCodeRefreshProbe) RefreshTokenStore() oauth.RefreshTokenStore {
	p.reads++
	if p.unwired {
		return nil
	}
	return fakeRefreshStorePresent{}
}

func (p *authCodeRefreshProbe) IssueRefreshToken(_ context.Context, userID, clientID, provider string, scopes []string, attributes map[string]string, familyID string, resources []string, details []byte, sid string, auth oauth.RefreshAuthContext, ttl time.Duration, jkt string) (string, error) {
	p.issues++
	p.record = &oauth.RefreshToken{UserID: userID, ClientID: clientID, Provider: provider, Scopes: scopes, Attributes: attributes, FamilyID: familyID, Resources: resources, AuthorizationDetails: details, SID: sid}
	p.auth, p.ttl, p.jkt = auth, ttl, jkt
	return "unit-managed-authcode-refresh", p.issueErr
}

func (p *authCodeRefreshProbe) RecordRefreshTokenIssued(_ core.HandlerContext, _, _ string, rotation bool) {
	p.events++
	p.rotation = rotation
}

func (p *authCodeRefreshProbe) SrvLogger() spi.Logger { return &recordingLogger{dst: &p.logs} }

type authCodeRefreshGrantCase struct {
	name                        string
	grants, scopes              []string
	unwired, fail               bool
	reads, issues, events, logs int
	refresh                     bool
}

func authCodeRefreshGrantCases() []authCodeRefreshGrantCase {
	offline := []string{"openid", core.ScopeOfflineAccess}
	allow := []string{core.GrantAuthorizationCode, core.GrantRefreshToken}
	return []authCodeRefreshGrantCase{
		{name: "nil legacy exact offline", scopes: offline, reads: 1, issues: 1, events: 1, refresh: true},
		{name: "empty legacy exact offline", grants: []string{}, scopes: offline, reads: 1, issues: 1, events: 1, refresh: true},
		{name: "explicit permits", grants: allow, scopes: offline, reads: 1, issues: 1, events: 1, refresh: true},
		{name: "duplicate exact", grants: []string{core.GrantRefreshToken, core.GrantAuthorizationCode, core.GrantRefreshToken}, scopes: offline, reads: 1, issues: 1, events: 1, refresh: true},
		{name: "code alone", grants: []string{core.GrantAuthorizationCode}, scopes: offline},
		{name: "unrelated grant", grants: []string{core.GrantCIBA}, scopes: offline},
		{name: "offline is not a grant", grants: []string{core.GrantAuthorizationCode, core.ScopeOfflineAccess}, scopes: offline},
		{name: "prefix alias", grants: []string{core.GrantAuthorizationCode, "xrefresh_token"}, scopes: offline},
		{name: "suffix alias", grants: []string{core.GrantAuthorizationCode, "refresh_token:extra"}, scopes: offline},
		{name: "case alias", grants: []string{core.GrantAuthorizationCode, "REFRESH_TOKEN"}, scopes: offline},
		{name: "trailing whitespace", grants: []string{core.GrantAuthorizationCode, "refresh_token "}, scopes: offline},
		{name: "leading whitespace", grants: []string{core.GrantAuthorizationCode, " refresh_token"}, scopes: offline},
		{name: "unsplit entry", grants: []string{core.GrantAuthorizationCode + " " + core.GrantRefreshToken}, scopes: offline},
		{name: "empty entry explicit denial", grants: []string{""}, scopes: offline},
		{name: "denied unwired no getter", grants: []string{core.GrantAuthorizationCode}, scopes: offline, unwired: true},
		{name: "denied outage unreachable", grants: []string{core.GrantAuthorizationCode}, scopes: offline, fail: true},
		{name: "authorized unwired", grants: allow, scopes: offline, unwired: true, reads: 1},
		{name: "authorized store failure", grants: allow, scopes: offline, fail: true, reads: 1, issues: 1, logs: 1},
		{name: "grant alone no offline", grants: allow, scopes: []string{"openid"}},
		{name: "nil effective scope", grants: allow},
		{name: "empty effective scope", grants: allow, scopes: []string{}},
		{name: "resource defaults no offline", grants: allow, scopes: []string{"profile"}},
		{name: "offline prefix not permission", grants: allow, scopes: []string{"xoffline_access"}},
		{name: "offline suffix not permission", grants: allow, scopes: []string{"offline_access:read"}},
		{name: "offline case not permission", grants: allow, scopes: []string{"OFFLINE_ACCESS"}},
		{name: "offline unsplit not permission", grants: allow, scopes: []string{"openid offline_access"}},
		{name: "non OIDC offline", grants: allow, scopes: []string{core.ScopeOfflineAccess}, reads: 1, issues: 1, events: 1, refresh: true},
	}
}

func TestAuthCodeRefreshGrant_Boundary(t *testing.T) {
	for _, tc := range authCodeRefreshGrantCases() {
		t.Run(tc.name, func(t *testing.T) {
			p := &authCodeRefreshProbe{unwired: tc.unwired}
			if tc.fail {
				p.issueErr = errors.New("unit-authcode-store-failure")
			}
			info := &oauth.AuthCode{UserID: "unit-user", Scopes: []string{"openid", core.ScopeOfflineAccess}, Attributes: map[string]string{"grant_types": core.GrantRefreshToken}}
			client := &core.Client{ID: "unit-client", GrantTypes: tc.grants, AllowedScopes: []string{core.ScopeOfflineAccess}, Attributes: map[string]string{"grant_types": core.GrantRefreshToken}}
			before, _ := json.Marshal([]any{info, client})
			resp := map[string]any{core.KeyAccessToken: "unit-access", core.KeyIDToken: "unit-id"}
			authCodeIssueRefresh(p, newBackgroundCtx(), client, info, tc.scopes, "", resp)
			if p.reads != tc.reads || p.issues != tc.issues || p.events != tc.events || len(p.logs) != tc.logs {
				t.Fatalf("reads/issues/events/logs=%d/%d/%d/%d want=%d/%d/%d/%d", p.reads, p.issues, p.events, len(p.logs), tc.reads, tc.issues, tc.events, tc.logs)
			}
			_, present := resp[core.KeyRefreshToken]
			if present != tc.refresh || resp[core.KeyAccessToken] != "unit-access" || resp[core.KeyIDToken] != "unit-id" || p.rotation {
				t.Fatal("refresh presence, independent access/ID or initial-event kind changed")
			}
			after, _ := json.Marshal([]any{info, client})
			if string(before) != string(after) || (tc.logs != 0 && p.logs[0] != "refresh token issue failed") {
				t.Fatal("approved input or failure log changed")
			}
		})
	}
}

func TestAuthCodeRefreshGrant_PreservesApprovedContext(t *testing.T) {
	p := &authCodeRefreshProbe{}
	info := &oauth.AuthCode{UserID: "unit-user", ClientID: "unit-client", Provider: "password", Scopes: []string{"profile", core.ScopeOfflineAccess}, Attributes: map[string]string{"locale": "en-US"}, Resources: []string{"unit-api"}, AuthorizationDetails: []byte(`[{"type":"unit","id":"a"}]`), SID: "unit-sid", AuthMethods: []string{"pwd", "mfa"}, ACR: "urn:unit:acr", AuthTime: time.Unix(1700000000, 123456789)}
	client := &core.Client{ID: info.ClientID, GrantTypes: []string{core.GrantAuthorizationCode, core.GrantRefreshToken}, RefreshTokenTTL: 17 * time.Minute}
	resp := map[string]any{}
	authCodeIssueRefresh(p, newBackgroundCtx(), client, info, info.Scopes, "unit-dpop-jkt", resp)
	want := &oauth.RefreshToken{UserID: info.UserID, ClientID: client.ID, Provider: info.Provider, Scopes: info.Scopes, Attributes: info.Attributes, Resources: info.Resources, AuthorizationDetails: info.AuthorizationDetails, SID: info.SID}
	if !reflect.DeepEqual(p.record, want) || p.ttl != client.RefreshTokenTTL || p.jkt != "unit-dpop-jkt" || p.issues != 1 || p.events != 1 || p.rotation {
		t.Fatal("approved context, empty family, TTL or sender constraint changed")
	}
	if !reflect.DeepEqual(p.auth, oauth.RefreshAuthContext{AMR: info.AuthMethods, ACR: info.ACR, AuthTime: info.AuthTime}) {
		t.Fatal("authentication or zero lineage fields changed")
	}
	if &p.record.Scopes[0] != &info.Scopes[0] || &p.record.Resources[0] != &info.Resources[0] || &p.record.AuthorizationDetails[0] != &info.AuthorizationDetails[0] || &p.auth.AMR[0] != &info.AuthMethods[0] {
		t.Fatal("approved stored aliases changed")
	}
	p.record.Attributes["alias"] = "shared"
	if info.Attributes["alias"] != "shared" {
		t.Fatal("approved attributes map replaced")
	}
}
