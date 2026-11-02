package tokengrant

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// Counts the handler's boundaries, not real persistence. HTTP tests separately
// exercise the real issue operation and refresh rotation with a memory store.
type deviceRefreshProbe struct {
	DeviceGrantDeps
	storeReads, issues, events int
	unwired                    bool
	issueErr                   error
	loggedErrors               []string
	record                     *oauth.RefreshToken
	auth                       oauth.RefreshAuthContext
	ttl                        time.Duration
	jkt                        string
	rotation                   bool
}

func (p *deviceRefreshProbe) RefreshTokenStore() oauth.RefreshTokenStore {
	p.storeReads++
	if p.unwired {
		return nil
	}
	return &struct{ oauth.RefreshTokenStore }{}
}

func (p *deviceRefreshProbe) IssueRefreshToken(_ context.Context, userID, clientID, provider string, scopes []string, attributes map[string]string, familyID string, resources []string, details []byte, sid string, auth oauth.RefreshAuthContext, ttl time.Duration, jkt string) (string, error) {
	p.issues++
	p.record = &oauth.RefreshToken{UserID: userID, ClientID: clientID, Provider: provider,
		Scopes: scopes, Attributes: attributes, FamilyID: familyID,
		Resources: resources, AuthorizationDetails: details, SID: sid}
	p.auth, p.ttl, p.jkt = auth, ttl, jkt
	return "unit-managed-device-refresh", p.issueErr
}

func (p *deviceRefreshProbe) RecordRefreshTokenIssued(_ core.HandlerContext, _, _ string, rotation bool) {
	p.events++
	p.rotation = rotation
}

func (p *deviceRefreshProbe) SrvLogger() spi.Logger {
	return &recordingLogger{dst: &p.loggedErrors}
}

type deviceRefreshCase struct {
	name        string
	scopes      []string
	grants      []string
	unwired     bool
	issueErr    error
	wantReads   int
	wantIssues  int
	wantEvents  int
	wantLogs    int
	wantRefresh bool
}

func deviceRefreshCases() []deviceRefreshCase {
	return []deviceRefreshCase{
		{name: "nil scopes"},
		{name: "empty scopes", scopes: []string{}},
		{name: "resource only", scopes: []string{"api:read"}},
		{name: "openid only", scopes: []string{"openid"}},
		{name: "substring prefix", scopes: []string{"xoffline_access"}},
		{name: "substring suffix", scopes: []string{"offline_access:extra"}},
		{name: "case alias", scopes: []string{"OFFLINE_ACCESS"}},
		{name: "one unsplit entry", scopes: []string{"api:read offline_access"}},
		{name: "allowlist alone", scopes: []string{"api:read"}, grants: []string{core.GrantDeviceCode, core.GrantRefreshToken}},
		{name: "unauthorized store error never reached", issueErr: errors.New("unit-store-failure")},
		{name: "exact legacy", scopes: []string{core.ScopeOfflineAccess}, wantReads: 1, wantIssues: 1, wantEvents: 1, wantRefresh: true},
		{name: "empty grants legacy", scopes: []string{core.ScopeOfflineAccess}, grants: []string{}, wantReads: 1, wantIssues: 1, wantEvents: 1, wantRefresh: true},
		{name: "exact explicit grants", scopes: []string{"api:read", core.ScopeOfflineAccess}, grants: []string{core.GrantDeviceCode, core.GrantRefreshToken}, wantReads: 1, wantIssues: 1, wantEvents: 1, wantRefresh: true},
		{name: "duplicate exact scope", scopes: []string{core.ScopeOfflineAccess, "api:read", core.ScopeOfflineAccess}, wantReads: 1, wantIssues: 1, wantEvents: 1, wantRefresh: true},
		{name: "unwired", scopes: []string{core.ScopeOfflineAccess}, unwired: true, wantReads: 1},
		{name: "explicit refresh grant denied", scopes: []string{core.ScopeOfflineAccess}, grants: []string{core.GrantDeviceCode}, wantReads: 1},
		{name: "authorized store failure", scopes: []string{core.ScopeOfflineAccess}, issueErr: errors.New("unit-store-failure"), wantReads: 1, wantIssues: 1, wantLogs: 1},
	}
}

func TestDeviceOfflineAccess_RefreshBoundary(t *testing.T) {
	for _, tc := range deviceRefreshCases() {
		t.Run(tc.name, func(t *testing.T) {
			p := &deviceRefreshProbe{unwired: tc.unwired, issueErr: tc.issueErr}
			dc := &oauth.DeviceCode{UserID: "unit-user", Provider: "password", Scopes: tc.scopes}
			client := &core.Client{ID: "unit-client", GrantTypes: tc.grants}
			before := append([]string(nil), dc.Scopes...)
			resp := map[string]any{core.KeyAccessToken: "unit-access", core.KeyIDToken: "unit-id"}
			deviceIssueRefresh(p, newBackgroundCtx(), client, dc, resp, "")
			if p.storeReads != tc.wantReads || p.issues != tc.wantIssues || p.events != tc.wantEvents || len(p.loggedErrors) != tc.wantLogs {
				t.Fatalf("reads/issues/events/logs=%d/%d/%d/%d; want %d/%d/%d/%d", p.storeReads, p.issues, p.events, len(p.loggedErrors), tc.wantReads, tc.wantIssues, tc.wantEvents, tc.wantLogs)
			}
			_, present := resp[core.KeyRefreshToken]
			if present != tc.wantRefresh || resp[core.KeyAccessToken] != "unit-access" || resp[core.KeyIDToken] != "unit-id" || p.rotation {
				t.Fatalf("refresh presence=%v; want %v; access/ID tokens and initial-issue metric must remain independent", present, tc.wantRefresh)
			}
			if !reflect.DeepEqual(before, append([]string(nil), dc.Scopes...)) {
				t.Fatal("stored scopes changed")
			}
			if tc.wantLogs != 0 && p.loggedErrors[0] != "refresh token issue failed" {
				t.Fatal("existing failure log changed")
			}
		})
	}
}

func TestDeviceOfflineAccess_PreservesApprovedContext(t *testing.T) {
	p := &deviceRefreshProbe{}
	dc := &oauth.DeviceCode{UserID: "unit-user", Provider: "password",
		Scopes:     []string{"api:read", core.ScopeOfflineAccess},
		Attributes: map[string]string{"department": "unit-department"}, Resources: []string{"unit-resource"}}
	client := &core.Client{ID: "unit-client", RefreshTokenTTL: 17 * time.Minute}
	resp := map[string]any{}
	before := time.Now()
	deviceIssueRefresh(p, newBackgroundCtx(), client, dc, resp, "unit-dpop-jkt")
	if p.issues != 1 || p.events != 1 || p.record == nil {
		t.Fatal("authorized issuance not observed")
	}
	want := &oauth.RefreshToken{UserID: dc.UserID, ClientID: client.ID, Provider: dc.Provider,
		Scopes: dc.Scopes, Attributes: dc.Attributes, Resources: dc.Resources}
	if !reflect.DeepEqual(p.record, want) || p.ttl != client.RefreshTokenTTL || p.jkt != "unit-dpop-jkt" {
		t.Fatal("approved context, empty family/SID/details, TTL or sender constraint changed")
	}
	if p.auth.AuthTime.Before(before) || p.auth.AuthTime.After(time.Now()) || len(p.auth.AMR) != 0 || p.auth.ACR != "" || p.auth.Generation != 0 || !p.auth.FamilyCreatedAt.IsZero() || p.auth.JTI != "" || len(p.auth.Roles) != 0 {
		t.Fatal("original device authentication/lineage context changed")
	}
	if &p.record.Scopes[0] != &dc.Scopes[0] || &p.record.Resources[0] != &dc.Resources[0] {
		t.Fatal("approved scope/resource slices were replaced")
	}
	p.record.Attributes["alias"] = "shared"
	if dc.Attributes["alias"] != "shared" {
		t.Fatal("approved attributes map was replaced")
	}
}
