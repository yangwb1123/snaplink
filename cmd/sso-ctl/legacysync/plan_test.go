package legacysync

import (
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestBuildPlanMapsLegacyIdentityAndPermissions(t *testing.T) {
	t.Parallel()
	data := legacyFixture(t)
	plan, err := buildPlan(data, map[string]string{"ERP_WEB": "sverp-web"},
		map[string]string{"ERP_WEB:ROOT": "admin"}, nil)
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	if got, want := len(plan.Users), 2; got != want {
		t.Fatalf("users = %d, want %d", got, want)
	}
	if plan.Users[0].ID != "alice" || plan.Users[0].ExternalID != "uuid-alice" {
		t.Fatalf("planned identity = %#v", plan.Users[0])
	}
	if plan.Users[1].Attributes[activeAttr] != "false" {
		t.Fatalf("inactive attribute = %q", plan.Users[1].Attributes[activeAttr])
	}
	key := assignmentKey{UserID: "alice", ClientID: "sverp-web"}
	wantRoles := []string{"admin", "legacy:ERP_WEB:ROOT", "legacy:ERP_WEB:override:grant-1"}
	if !slices.Equal(plan.Assignments[key], wantRoles) {
		t.Fatalf("assignment = %v, want %v", plan.Assignments[key], wantRoles)
	}
	if got, want := plan.Source.Grants, 1; got != want {
		t.Fatalf("source grants = %d, want %d", got, want)
	}
}

func TestBuildPlanRejectsUnsafeUsers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		users []legacyUser
	}{
		{name: "invalid login", users: []legacyUser{{LoginID: "bad-login", Hash: testHash(t)}}},
		{name: "duplicate login", users: []legacyUser{
			{LoginID: "Alice", Hash: testHash(t)}, {LoginID: "alice", Hash: testHash(t)},
		}},
		{name: "invalid hash", users: []legacyUser{{LoginID: "alice", Hash: "plaintext"}}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := buildPlan(legacyData{Users: tt.users}, nil, nil, nil); err == nil {
				t.Fatal("buildPlan succeeded, want error")
			}
		})
	}
}

func TestBuildPlanMapsConflictingLogin(t *testing.T) {
	t.Parallel()
	data := legacyData{Users: []legacyUser{{LegacyID: "1", UUID: "uuid-admin", LoginID: "admin",
		Hash: testHash(t), Status: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()}}}
	plan, err := buildPlan(data, nil, nil, map[string]string{"admin": "legacy_admin"})
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	if plan.Users[0].ID != "legacy_admin" || plan.Users[0].Attributes["sv_sso:login_id"] != "admin" {
		t.Fatalf("mapped user = %#v", plan.Users[0])
	}
}

func legacyFixture(t *testing.T) legacyData {
	t.Helper()
	now := time.Unix(1_700_000_000, 0)
	return legacyData{
		Users: []legacyUser{
			{LegacyID: "1", UUID: "uuid-alice", LoginID: "alice", Hash: testHash(t), Name: "Alice",
				Status: 1, CreatedAt: now, UpdatedAt: now},
			{LegacyID: "2", UUID: "uuid-bob", LoginID: "bob", Hash: testHash(t), Name: "Bob",
				Status: 0, CreatedAt: now, UpdatedAt: now},
		},
		Roles: []legacyRole{{AppCode: "ERP_WEB", ID: "role-1", Code: "ROOT", Name: "Root", Status: 1,
			Permissions: []string{"legacy:menu:1:view", "legacy:menu:1:view"}}},
		Grants: []legacyGrant{{AppCode: "ERP_WEB", LoginID: "alice", RoleID: "role-1", RoleRowID: "grant-1"}},
		Overrides: []legacyOverride{{AppCode: "ERP_WEB", LoginID: "alice", RoleRowID: "grant-1",
			ActionID: "action-1", Action: "READ", MenuID: "menu-1"}},
	}
}

func testHash(t *testing.T) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("test-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	return string(hash)
}
