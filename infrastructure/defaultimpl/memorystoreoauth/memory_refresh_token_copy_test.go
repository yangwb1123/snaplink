package memorystoreoauth

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/protocols/oauth"
)

func TestMemoryRefreshTokenStore_InspectDoesNotAliasPayload(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryRefreshTokenStore()
	input := refreshTokenFixture()
	if err := store.Issue(ctx, "refresh-1", input); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	mutateRefreshToken(input, "caller-mutated")
	got, err := store.Inspect(ctx, "refresh-1")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	assertRefreshTokenPayload(t, got)

	mutateRefreshToken(got, "returned-mutated")
	later, err := store.Inspect(ctx, "refresh-1")
	if err != nil {
		t.Fatalf("second Inspect: %v", err)
	}
	assertRefreshTokenPayload(t, later)

	consumed, err := store.Consume(ctx, "refresh-1")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	assertRefreshTokenPayload(t, consumed)
}

func refreshTokenFixture() *oauth.RefreshToken {
	return &oauth.RefreshToken{
		UserID:               "user-1",
		ClientID:             "client-1",
		Provider:             "password",
		Scopes:               []string{"openid", "profile"},
		Attributes:           map[string]string{"role": "reader"},
		IssuedAt:             time.Unix(100, 0),
		ExpiresAt:            time.Now().Add(time.Hour),
		FamilyID:             "family-1",
		JTI:                  "jti-1",
		Resources:            []string{"https://api.example.test"},
		AuthorizationDetails: []byte(`[{"type":"openid_credential"}]`),
		SID:                  "sid-1",
		Amr:                  []string{"pwd", "mfa"},
		Acr:                  "urn:example:loa:2",
		AuthTime:             time.Unix(90, 0),
		ConfirmationJKT:      "jkt-1",
		Generation:           2,
		FamilyCreatedAt:      time.Unix(10, 0),
		Roles:                []string{"member", "auditor"},
	}
}

func mutateRefreshToken(token *oauth.RefreshToken, value string) {
	token.Scopes[0] = value
	token.Attributes["role"] = value
	token.Resources[0] = "https://" + value + ".example.test"
	token.AuthorizationDetails[0] = 'x'
	token.Amr[0] = value
	token.Roles[0] = value
}

func assertRefreshTokenPayload(t *testing.T, token *oauth.RefreshToken) {
	t.Helper()
	if token.UserID != "user-1" || token.ClientID != "client-1" || token.Provider != "password" {
		t.Fatalf("identity fields changed: %+v", token)
	}
	if len(token.Scopes) != 2 || token.Scopes[0] != "openid" || token.Scopes[1] != "profile" {
		t.Fatalf("scopes changed: %v", token.Scopes)
	}
	if token.Attributes["role"] != "reader" {
		t.Fatalf("attributes changed: %v", token.Attributes)
	}
	if len(token.Resources) != 1 || token.Resources[0] != "https://api.example.test" {
		t.Fatalf("resources changed: %v", token.Resources)
	}
	if string(token.AuthorizationDetails) != `[{"type":"openid_credential"}]` {
		t.Fatalf("authorization details changed: %s", token.AuthorizationDetails)
	}
	if len(token.Amr) != 2 || token.Amr[0] != "pwd" || token.Amr[1] != "mfa" {
		t.Fatalf("amr changed: %v", token.Amr)
	}
	if len(token.Roles) != 2 || token.Roles[0] != "member" || token.Roles[1] != "auditor" {
		t.Fatalf("roles changed: %v", token.Roles)
	}
	if token.FamilyID != "family-1" || token.JTI != "jti-1" || token.SID != "sid-1" || token.Acr != "urn:example:loa:2" || token.ConfirmationJKT != "jkt-1" || token.Generation != 2 {
		t.Fatalf("lineage fields changed: %+v", token)
	}
	if !token.IssuedAt.Equal(time.Unix(100, 0)) || !token.AuthTime.Equal(time.Unix(90, 0)) || !token.FamilyCreatedAt.Equal(time.Unix(10, 0)) {
		t.Fatalf("time fields changed: %+v", token)
	}
}
