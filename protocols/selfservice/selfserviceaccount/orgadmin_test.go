package selfserviceaccount

import (
	"encoding/base64"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

func TestValidTenantRole(t *testing.T) {
	valid := []core.TenantRole{core.TenantRoleMember, core.TenantRoleAdmin, core.TenantRoleGuest}
	for _, r := range valid {
		if !validTenantRole(r) {
			t.Errorf("validTenantRole(%q) = false, want true", r)
		}
	}
	for _, r := range []core.TenantRole{"", "owner", "Admin", "root"} {
		if validTenantRole(r) {
			t.Errorf("validTenantRole(%q) = true, want false", r)
		}
	}
}

func TestMintInviteToken_UniqueAndDecodable(t *testing.T) {
	a, err := mintInviteToken()
	if err != nil {
		t.Fatalf("mintInviteToken: %v", err)
	}
	b, err := mintInviteToken()
	if err != nil {
		t.Fatalf("mintInviteToken: %v", err)
	}
	if a == b {
		t.Fatalf("two mints returned the same token — not random")
	}
	// 32 random bytes, base64url, no padding — a live credential, so it must
	// carry full entropy.
	raw, err := base64.RawURLEncoding.DecodeString(a)
	if err != nil {
		t.Fatalf("token is not valid base64url: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("token entropy = %d bytes, want 32", len(raw))
	}
}
