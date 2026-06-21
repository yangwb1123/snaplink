package serverbuildauthn

import (
	"errors"
	"fmt"
	"strings"

	"github.com/snaplink/sso/config"

	"github.com/snaplink/sso/infrastructure/defaultimpl"

	sqlitestores "github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"

	"github.com/snaplink/sso/shared/security"
)

func BuildPairwiseSubjectStore(cfg config.PairwiseSubjectsConfig) (security.PairwiseSubjectStore, string, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		return security.NewMemoryPairwiseSubjectStore(), "memory (single-replica only)", nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, "", errors.New("server.pairwise_subjects.sqlite.dsn required when backend=sqlite")
		}
		store, err := sqlitestores.NewPairwiseSubjectStore(cfg.SQLite.DSN)
		if err != nil {
			return nil, "", err
		}
		return store, "sqlite (cluster-shared)", nil
	default:
		return nil, "", fmt.Errorf("unknown server.pairwise_subjects.backend %q", cfg.Backend)
	}
}

// BuildAccountLockout picks the lockout backend. memory keeps the
// single-replica defense; sqlite shares the failure counter so an
// attacker rotating across replicas can't stay under each replica's
// local threshold. Policy overrides (MaxFailures / LockoutDuration
// / FailureWindow) are applied identically to both backends.
func BuildAccountLockout(cfg config.AccountLockoutConfig) (security.AccountLockout, string, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		l := security.NewMemoryAccountLockout()
		if cfg.MaxFailures > 0 {
			l.MaxFailures = cfg.MaxFailures
		}
		if cfg.LockoutDuration > 0 {
			l.LockoutDuration = cfg.LockoutDuration
		}
		if cfg.FailureWindow > 0 {
			l.FailureWindow = cfg.FailureWindow
		}
		return l, "memory (single-replica only)", nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, "", errors.New("security.account_lockout.sqlite.dsn required when backend=sqlite")
		}
		l, err := sqlitestores.NewAccountLockout(cfg.SQLite.DSN)
		if err != nil {
			return nil, "", err
		}
		if cfg.MaxFailures > 0 {
			l.MaxFailures = cfg.MaxFailures
		}
		if cfg.LockoutDuration > 0 {
			l.LockoutDuration = cfg.LockoutDuration
		}
		if cfg.FailureWindow > 0 {
			l.FailureWindow = cfg.FailureWindow
		}
		return l, "sqlite (cluster-shared)", nil
	default:
		return nil, "", fmt.Errorf("unknown security.account_lockout.backend %q", cfg.Backend)
	}
}

// BuildSubjectClientIndex picks the security.SubjectClientIndex backend that
// drives OIDC BCL multi-RP fan-out. memory keeps the single-replica
// story; sqlite shares the index so a logout reaching any replica
// fans out to every client a subject has touched cluster-wide.
func BuildSubjectClientIndex(cfg config.BCLIndexConfig) (security.SubjectClientIndex, string, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		return defaultimpl.NewMemorySubjectClientIndex(), "memory (single-replica only)", nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, "", errors.New("backchannel_logout.index.sqlite.dsn required when backend=sqlite")
		}
		idx, err := sqlitestores.NewSubjectClientIndex(cfg.SQLite.DSN)
		if err != nil {
			return nil, "", err
		}
		return idx, "sqlite (cluster-shared)", nil
	default:
		return nil, "", fmt.Errorf("unknown backchannel_logout.index.backend %q", cfg.Backend)
	}
}

// BuildJTIReplayStore picks the JTI replay backend. memory keeps
// the single-replica defense story; sqlite shares the seen-set
// across the cluster so a replay routed to a different replica still
// gets rejected.
func BuildJTIReplayStore(cfg config.JTIReplayConfig) (security.JTIReplayStore, string, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		return defaultimpl.NewMemoryJTIReplayStore(), "memory (single-replica only)", nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, "", errors.New("security.jti_replay.sqlite.dsn required when backend=sqlite")
		}
		store, err := sqlitestores.NewJTIReplayStore(cfg.SQLite.DSN)
		if err != nil {
			return nil, "", err
		}
		return store, "sqlite (cluster-shared)", nil
	default:
		return nil, "", fmt.Errorf("unknown security.jti_replay.backend %q", cfg.Backend)
	}
}

// buildAuthenticatorReplayStore resolves the replay-defense store the keypair
// (nonce) and TOTP (consumed-code) authenticators record against. Unlike the
// DPoP/JAR/assertion jti store it is ALWAYS present: the keypair signature and
// TOTP code each replay within their bounded skew/step window, so a shipped
// binary that omits the store is replay-vulnerable by default. When the
// operator already opted into jti replay protection we reuse that backend (so
// sqlite stays cluster-shared and the defense doesn't fork across replicas);
// otherwise we default to an in-memory store so the out-of-the-box binary is
// safe on a single replica. Reuses the existing security.JTIReplayStore SPI —
// a nonce / consumed (user, step) is just another "have I seen this before"
// check. mode is for the boot log.
func buildAuthenticatorReplayStore(cfg config.JTIReplayConfig) (security.JTIReplayStore, string, error) {
	if cfg.Enabled {
		return BuildJTIReplayStore(cfg)
	}
	return defaultimpl.NewMemoryJTIReplayStore(), "memory (default; enable security.jti_replay for cluster-shared)", nil
}
