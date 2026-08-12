package sqlite_test

import (
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
)

// TestMaxVersions_AllReturnPositive exercises every per-store
// XxxMaxVersion accessor. cmd compares these against the live DB at boot
// (migrate.CheckSchema) so an older binary fails loud on a forward-migrated
// schema; the contract here is only that every store declares a positive
// baseline version. The multi-migration stores (sessions/clients/refresh)
// MUST report > 1 because they have appended migrations.
func TestMaxVersions_AllReturnPositive(t *testing.T) {
	t.Parallel()
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
		{"Consent", sqlite.ConsentMaxVersion},
		{"Revocations", sqlite.RevocationsMaxVersion},
	}
	for _, v := range all {
		if got := v.fn(); got < 1 {
			t.Errorf("%sMaxVersion() = %d, want >= 1", v.name, got)
		}
	}

	// Stores with appended migrations must report the higher version (proves
	// MaxVersion reads the slice, not a hardcoded 1).
	if got := sqlite.SessionsMaxVersion(); got != 5 {
		t.Errorf("SessionsMaxVersion() = %d, want 5 (v5 session authorization context)", got)
	}
	if got := sqlite.UsersMaxVersion(); got != 2 {
		t.Errorf("UsersMaxVersion() = %d, want 2 (v2 adds SCIM userName uniqueness)", got)
	}
	if got := sqlite.RefreshTokensMaxVersion(); got != 9 {
		t.Errorf("RefreshTokensMaxVersion() = %d, want 9 (v7 bounds the family reuse ledger, v8 adds jti for refresh-introspect thumbprints, v9 adds roles for the tenant-membership claim)", got)
	}
	if got := sqlite.AuthCodesMaxVersion(); got != 4 {
		t.Errorf("AuthCodesMaxVersion() = %d, want 4 (v3 adds requested_claims for the OIDC §5.5 claims parameter, v4 adds auth_time/amr/acr/resources/authorization_details/sid RFC 9068 auth context)", got)
	}
}
