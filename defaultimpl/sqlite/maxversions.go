package sqlite

import "github.com/snaplink/sso/migrate"

// Each function below returns the highest migration version declared for
// its store. cmd compares these against the live DB at boot via
// migrate.CheckSchema so that an older binary running against a
// forward-migrated database fails loud instead of silently serving on a
// schema it doesn't understand (the canary-rollback foot-gun).
//
// Stores that use ensureSchema have exactly one migration (v1) whose SQL
// is the baseline CREATE TABLE block; that is expressed here as 1 rather
// than by referencing the unexported schema string, since ensureSchema
// does not expose a named slice.

// SessionsMaxVersion returns the highest migration version declared for
// the sessions store.
func SessionsMaxVersion() int { return 1 }

// UsersMaxVersion returns the highest migration version declared for the
// users store.
func UsersMaxVersion() int { return 1 }

// ClientsMaxVersion returns the highest migration version declared for
// the clients store.
func ClientsMaxVersion() int { return migrate.MaxVersion(clientMigrations) }

// RefreshTokensMaxVersion returns the highest migration version declared
// for the refresh_tokens store.
func RefreshTokensMaxVersion() int { return migrate.MaxVersion(refreshTokenMigrations) }

// AuthCodesMaxVersion returns the highest migration version declared for
// the auth_codes store.
func AuthCodesMaxVersion() int { return 1 }

// CIBARequestsMaxVersion returns the highest migration version declared
// for the ciba_requests store.
func CIBARequestsMaxVersion() int { return migrate.MaxVersion(cibaMigrations) }

// DeviceCodesMaxVersion returns the highest migration version declared
// for the device_codes store.
func DeviceCodesMaxVersion() int { return 1 }

// PARMaxVersion returns the highest migration version declared for the
// par store.
func PARMaxVersion() int { return 1 }

// JTIReplayMaxVersion returns the highest migration version declared for
// the jti_replay store.
func JTIReplayMaxVersion() int { return 1 }

// MFAChallengesMaxVersion returns the highest migration version declared
// for the mfa_challenges store.
func MFAChallengesMaxVersion() int { return 1 }

// PushApprovalsMaxVersion returns the highest migration version declared
// for the push_approvals store.
func PushApprovalsMaxVersion() int { return 1 }

// SubjectClientIndexMaxVersion returns the highest migration version
// declared for the subject_client_index store.
func SubjectClientIndexMaxVersion() int { return 1 }

// PairwiseMaxVersion returns the highest migration version declared for
// the pairwise store.
func PairwiseMaxVersion() int { return 1 }

// AccountLockoutMaxVersion returns the highest migration version declared
// for the account_lockout store.
func AccountLockoutMaxVersion() int { return 1 }

// IPFailureCounterMaxVersion returns the highest migration version
// declared for the ip_failure_counter store.
func IPFailureCounterMaxVersion() int { return 1 }

// RecentLoginMaxVersion returns the highest migration version declared
// for the recent_login store.
func RecentLoginMaxVersion() int { return 1 }

// DeviceSecretsMaxVersion returns the highest migration version declared
// for the device_secrets store (Native SSO 1.0).
func DeviceSecretsMaxVersion() int { return 1 }
