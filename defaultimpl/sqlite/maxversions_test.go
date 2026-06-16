package sqlite_test

import (
	"testing"

	"github.com/snaplink/sso/defaultimpl/sqlite"
)

// TestMaxVersions_AllReturnPositive exercises every per-store
// XxxMaxVersion accessor. cmd compares these against the live DB at boot
// (migrate.CheckSchema) so an older binary fails loud on a forward-migrated
// schema; the contract here is only that every store declares a positive
// baseline version. The multi-migration stores (sessions/clients/refresh)
// MUST report > 1 because they have appended migrations.
func TestMaxVersions_AllReturnPositive(t *testing.T) {
	type vfn struct {
		name string
		fn   func() int
	}
	all := []vfn{
		{"Sessions", sqlite.SessionsMaxVersion},
		{"Users", sqlite.UsersMaxVersion},
		{"Clients", sqlite.ClientsMaxVersion},
		{"RefreshTokens", sqlite.RefreshTokensMaxVersion},
		{"AuthCodes", sqlite.AuthCodesMaxVersion},
		{"CIBARequests", sqlite.CIBARequestsMaxVersion},
		{"DeviceCodes", sqlite.DeviceCodesMaxVersion},
		{"PAR", sqlite.PARMaxVersion},
		{"JTIReplay", sqlite.JTIReplayMaxVersion},
		{"MFAChallenges", sqlite.MFAChallengesMaxVersion},
		{"PushApprovals", sqlite.PushApprovalsMaxVersion},
		{"TOTPFactors", sqlite.TOTPFactorsMaxVersion},
		{"PasswordResetTokens", sqlite.PasswordResetTokensMaxVersion},
		{"EmailChangeTokens", sqlite.EmailChangeTokensMaxVersion},
		{"SubjectClientIndex", sqlite.SubjectClientIndexMaxVersion},
		{"Pairwise", sqlite.PairwiseMaxVersion},
		{"AccountLockout", sqlite.AccountLockoutMaxVersion},
		{"IPFailureCounter", sqlite.IPFailureCounterMaxVersion},
		{"RecentLogin", sqlite.RecentLoginMaxVersion},
		{"DeviceSecrets", sqlite.DeviceSecretsMaxVersion},
		{"Invitations", sqlite.InvitationsMaxVersion},
		{"TenantMemberships", sqlite.TenantMembershipsMaxVersion},
	}
	for _, v := range all {
		if got := v.fn(); got < 1 {
			t.Errorf("%sMaxVersion() = %d, want >= 1", v.name, got)
		}
	}

	// Stores with appended migrations must report the higher version (proves
	// MaxVersion reads the slice, not a hardcoded 1).
	if got := sqlite.SessionsMaxVersion(); got != 3 {
		t.Errorf("SessionsMaxVersion() = %d, want 3 (v3 tenant binding)", got)
	}
	if got := sqlite.RefreshTokensMaxVersion(); got != 2 {
		t.Errorf("RefreshTokensMaxVersion() = %d, want 2 (rotation windows)", got)
	}
}
