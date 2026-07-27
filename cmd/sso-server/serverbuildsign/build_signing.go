package serverbuildsign

import (
	"context"
	"crypto"
	"fmt"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oidc"
	"github.com/yangwb1123/snaplink/shared/spi"

	"github.com/yangwb1123/snaplink/protocols/caep"

	"github.com/yangwb1123/snaplink/config"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"

	sqlitestores "github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"

	"github.com/yangwb1123/snaplink/platform/metrics"
	"github.com/yangwb1123/snaplink/shared/security/fipspolicy"
)

// buildApp wires every SDK component the config asks for and returns them
// as a bundle so HTTP and gRPC entrypoints can share instances.
// SigningIssuer is the interface set cmd needs from the JWT signing
// issuer — satisfied by both *defaultimpl.Ed25519JWTIssuer and
// *defaultimpl.ECDSAJWTIssuer. The EdDSA-specific scheduled rotation
// loop is reached via a separate type assertion (ECDSA has no
// StartRotation today).
type SigningIssuer interface {
	sso.TokenIssuer
	oidc.IDTokenIssuer
	sso.LogoutTokenIssuer
	// caep.JWTSigner (SignJWT) lets the same key mint Security Event
	// Tokens (RFC 8417) for the CAEP transmitter — one key, one JWKS
	// entry, every JWT shape.
	caep.JWTSigner
}

// BuildSigningIssuer constructs the JWT signing issuer for the configured
// algorithm, optionally backed by an external KMS/HSM signer registered
// via RegisterExternalSigner. It returns the issuer, its canonical alg
// name (for logging + rotation gating), and any wiring error. An external
// signer is bridged into the issuer's seam via defaultimpl/cryptosigner;
// a mismatched key shape fails closed here at startup.
//
// The third return value is the instrumented external signer (nil for the
// in-process key path) — the caller hands it to AppendReadyCheck so a
// wedged KMS/HSM trips /readyz.
func BuildSigningIssuer(sc config.SigningConfig, srv config.ServerConfig, m *metrics.Metrics, logger spi.Logger) (SigningIssuer, string, crypto.Signer, error) {
	extSigner, extKID, err := resolveExternalSigner(sc, m, logger)
	if err != nil {
		return nil, "", nil, err
	}

	revStore, err := BuildRevocationStore(sc)
	if err != nil {
		return nil, "", nil, err
	}

	alg := strings.ToLower(strings.TrimSpace(sc.Alg))
	// Single centralized gate (AGENTS.md: don't scatter FIPS-awareness
	// across crypto call sites) — checked before any alg-specific issuer
	// is constructed, so a rejected alg never partially wires a signer.
	if err := fipspolicy.ValidateIssuerAlg(sc.FIPSMode, alg, sc.FIPSAllowedAlgs); err != nil {
		return nil, "", nil, err
	}

	switch alg {
	case "", "eddsa", "ed25519":
		return buildEd25519SigningIssuer(srv, extSigner, extKID, revStore, m)
	case "es256", "ecdsa":
		return buildECDSASigningIssuer(srv, extSigner, extKID, revStore, m)
	case "rs256", "ps256", "rsa":
		return buildRSASigningIssuer(alg, srv, extSigner, extKID, revStore, m)
	default:
		return nil, "", nil, fmt.Errorf("keys.signing.alg %q unsupported (supported: eddsa, es256, rs256, ps256)", alg)
	}
}

// BuildRevocationStore constructs the optional durable RevocationStore from
// keys.signing.revocation_backend so access-token revocations survive a
// restart (defaultimpl.RevocationStore). "" = nil (in-process only). The
// sqlite store's *sql.DB lives for the process lifetime like the signing
// issuer it backs (no /readyz ping wired yet — a follow-on).
func BuildRevocationStore(sc config.SigningConfig) (defaultimpl.RevocationStore, error) {
	switch strings.ToLower(strings.TrimSpace(sc.RevocationBackend)) {
	case "":
		return nil, nil
	case "memory":
		return defaultimpl.NewMemoryRevocationStore(), nil
	case "sqlite":
		dsn := strings.TrimSpace(sc.RevocationDSN)
		if dsn == "" {
			return nil, fmt.Errorf("keys.signing.revocation_backend sqlite requires keys.signing.revocation_dsn")
		}
		st, err := sqlitestores.NewRevocationStore(dsn)
		if err != nil {
			return nil, fmt.Errorf("keys.signing.revocation: %w", err)
		}
		return st, nil
	default:
		return nil, fmt.Errorf("keys.signing.revocation_backend %q unsupported (supported: memory, sqlite)", sc.RevocationBackend)
	}
}

// seedRevocations re-seeds the issuer's in-process deny-set from the durable
// store at boot so a pre-restart revocation is honored again. nil store = no-op.
func seedRevocations(iss interface {
	SeedRevocations(context.Context) error
}, store defaultimpl.RevocationStore) error {
	if store == nil {
		return nil
	}
	return iss.SeedRevocations(context.Background())
}

// PushApprovalStoreIface adapts the sqlite-typed handle into the
// defaultimpl interface — nil handle in → nil interface out so the
// callback wiring's nil-check works (a typed-nil-in-interface
// would slip past it).
func PushApprovalStoreIface(s *sqlitestores.PushApprovalStore) defaultimpl.PushApprovalStore {
	if s == nil {
		return nil
	}
	return s
}

// RunPushApprovalPrune wakes every interval and calls
// PushApprovalStore.PruneExpired to bound the table size.
// Operators wanting bounded push-approval growth across an
// indefinite deployment lifetime wire this through
// mfa.provider.push.prune_interval rather than running external
// cron.
//
// Same shutdown contract as the audit / snapshot retention loops:
// close done on exit; Prune errors logged but don't tear down the
// loop. First prune fires after the first interval, not immediately.
func RunPushApprovalPrune(ctx context.Context, done chan<- struct{}, store *sqlitestores.PushApprovalStore, interval time.Duration, logger spi.Logger, m *metrics.Metrics) {
	defer close(done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			prunePushApprovalSafe(ctx, store, logger, m)
		}
	}
}

// prunePushApprovalSafe wraps one PushApprovalStore.PruneExpired call in
// recover(), invoked from a PERMANENT background goroutine — an unrecovered
// panic here would crash the whole process, not just this prune tick. Same
// rationale as serverbuildstore.pruneCIBASafe (identical shape, sibling
// package — see that doc comment).
func prunePushApprovalSafe(ctx context.Context, store *sqlitestores.PushApprovalStore, logger spi.Logger, m *metrics.Metrics) {
	defer func() {
		if rec := recover(); rec != nil {
			logger.Error("push approvals prune panic recovered", "panic", rec)
		}
	}()
	deleted, err := store.PruneExpired(ctx)
	if err != nil {
		logger.Error("push approvals prune failed", "error", err)
		if m != nil {
			m.RetentionPruneErrorTotal.WithLabelValues("push_approvals").Inc()
		}
		return
	}
	if deleted > 0 {
		logger.Info("push approvals pruned", "deleted", deleted)
		if m != nil {
			m.RetentionPrunedTotal.WithLabelValues("push_approvals").Add(float64(deleted))
		}
	}
}
