package serverbuildplatform

import (
	"errors"
	"fmt"
	"os"
	"strings"

	goredis "github.com/redis/go-redis/v9"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/spi"

	"github.com/snaplink/sso/protocols/caep"

	"github.com/snaplink/sso/config"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	redisbackend "github.com/snaplink/sso/infrastructure/redis"

	"github.com/snaplink/sso/domains/federation"

	"github.com/snaplink/sso/platform/metrics"

	"github.com/snaplink/sso/shared/security"
)

// BuildSPIFFEOption assembles the WithSPIFFEJWTSVID option from config,
// loading the SPIRE trust-bundle JWKS from disk into a StaticJWKS. It
// fails LOUD on any missing required field — there is no safe default for
// the trust domain, the audience the SVID must bind to, or the trust
// bundle itself, and silently degrading would leave an operator believing
// SVID acceptance is on when it isn't (or, worse, accepting tokens it
// shouldn't).
// SubordinateConstraints translates the YAML §6.2 constraints config onto the
// SDK federation.EntityConstraints authored into a Subordinate Statement.
// Returns nil when the operator configured no constraints (so the statement
// carries no constraints claim). Preserves the pointer/empty-slice distinctions
// the SDK relies on (max_path_length 0 = "no intermediates"; a non-nil empty
// allowed_entity_types = "only federation_entity"); a naming_constraints object
// is emitted only when at least one of permitted/excluded is non-empty.
func SubordinateConstraints(c *config.SubordinateConstraintsConfig) *federation.EntityConstraints {
	if c == nil {
		return nil
	}
	out := &federation.EntityConstraints{MaxPathLength: c.MaxPathLength}
	if len(c.NamingConstraintsPermitted) > 0 || len(c.NamingConstraintsExcluded) > 0 {
		out.NamingConstraints = &federation.NamingConstraints{
			Permitted: append([]string(nil), c.NamingConstraintsPermitted...),
			Excluded:  append([]string(nil), c.NamingConstraintsExcluded...),
		}
	}
	if c.AllowedEntityTypes != nil {
		types := append([]string(nil), (*c.AllowedEntityTypes)...)
		out.AllowedEntityTypes = &types
	}
	return out
}

func BuildSPIFFEOption(cfg config.SPIFFEConfig) (sso.Option, error) {
	if cfg.TrustDomain == "" {
		return nil, errors.New("spiffe.trust_domain required when spiffe.enabled")
	}
	if cfg.Audience == "" {
		return nil, errors.New("spiffe.audience required when spiffe.enabled")
	}
	if cfg.JWKSFile == "" {
		return nil, errors.New("spiffe.jwks_file required when spiffe.enabled")
	}
	doc, err := os.ReadFile(cfg.JWKSFile)
	if err != nil {
		return nil, fmt.Errorf("read spiffe.jwks_file: %w", err)
	}
	source, err := security.ParseStaticJWKS(doc)
	if err != nil {
		return nil, fmt.Errorf("parse spiffe trust bundle: %w", err)
	}
	var vopts []security.SPIFFEValidatorOption
	if cfg.MaxClockSkew > 0 {
		vopts = append(vopts, security.WithSPIFFEMaxClockSkew(cfg.MaxClockSkew))
	}
	return sso.WithSPIFFEJWTSVID(cfg.TrustDomain, cfg.Audience, source, vopts...), nil
}

// CaepSubjectMode maps the YAML subject_mode string onto the SDK enum. It
// fails LOUD on an unrecognised value rather than silently defaulting —
// the wrong mode is a wrong-subject-revocation risk, so an operator typo
// must surface, not degrade.
func CaepSubjectMode(raw string) (caep.SubjectMapMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "opaque":
		return caep.SubjectMapOpaque, nil
	case "iss_sub", "iss-sub":
		return caep.SubjectMapIssSub, nil
	default:
		return 0, fmt.Errorf("unknown caep.receiver subject_mode %q (want opaque|iss_sub)", raw)
	}
}

// BuildCAEPReceiverOption assembles the WithCAEPReceiver option — the
// INBOUND half of OpenID Shared Signals. It loads each trusted
// transmitter's trust-bundle JWKS from disk, composes the revocation seam
// (sessions + refresh tokens) from the already-built stores, and wires a
// dedicated JTI-replay store for the SET jti namespace.
//
// It fails LOUD on any missing required field (audience, no transmitters, a
// transmitter without issuer/jwks_file, a bad subject_mode) — a half-wired
// receiver would either accept nothing or, worse, mis-map a subject, so a
// misconfiguration must stop boot, not degrade.
//
// The receiver's revocation reuses the SAME seams /token/revoke-all drives:
// the RefreshTokenSubjectIndex (when the refresh store supports it) + the
// SessionManager. A receiver that could revoke NOTHING (no session manager
// AND no subject-index refresh store) is rejected.
//
// NOT wired here: caep.WithTrustedDeviceRevocation. The library-level
// StoreRevoker.TrustedDevices leg exists and is unit-tested (see
// protocols/caep/revoker.go), but cmd/sso-server never constructs a
// core.TrustedDeviceStore in the first place — sso.WithTrustedDeviceStore is
// not called anywhere under cmd/, the same gap RecoveryCodeStore already has
// (no config.SelfService.TrustedDevices surface, no
// serverbuildstore.BuildTrustedDeviceStore). Wiring it for real needs a YAML
// config surface + store construction before this function could even
// receive a non-nil store to pass to WithTrustedDeviceRevocation, so it is
// intentionally left as follow-up scope rather than done here.
func BuildCAEPReceiverOption(cfg config.CAEPReceiverConfig, sessionMgr sso.SessionManager, refreshStore oauth.RefreshTokenStore, clientStore sso.ClientStore, userProvider sso.UserProvider, recorder *audit.Recorder, metricsReg *metrics.Metrics, rdb goredis.Cmdable, logger spi.Logger) (sso.Option, error) {
	if cfg.Audience == "" {
		return nil, errors.New("caep.receiver.audience required when caep.receiver.enabled")
	}
	if len(cfg.Transmitters) == 0 {
		return nil, errors.New("caep.receiver.transmitters requires at least one entry when caep.receiver.enabled")
	}

	transmitters, err := buildCAEPTransmitters(cfg.Transmitters)
	if err != nil {
		return nil, err
	}

	// Revocation seam: the RefreshTokenSubjectIndex (bulk subject revoke,
	// when the refresh store supports it) + the SessionManager. Identical to
	// the seams /token/revoke-all + the compliance Eraser use. No
	// caep.WithTrustedDeviceRevocation(...) leg — see the func doc above for
	// why (no TrustedDeviceStore is ever constructed under cmd/ today).
	var subjectIndex oauth.RefreshTokenSubjectIndex
	if idx, ok := refreshStore.(oauth.RefreshTokenSubjectIndex); ok {
		subjectIndex = idx
	}
	revoker, err := caep.NewStoreRevoker(sessionMgr, subjectIndex, clientStore)
	if err != nil {
		return nil, err
	}

	// Dedicated replay store for the SET jti namespace (ssf:<iss>:<jti>),
	// independent of the DPoP/actor-token replay store. Memory keeps the
	// single-replica story; a multi-replica receiver deployment SHOULD swap
	// this for a cluster-shared store so a replayed SET routed to a
	// different replica is still rejected. The receiver itself fails CLOSED
	// on any MarkSeen error regardless of backend.
	// Cluster-shared replay store when a Redis cluster is wired, so a replayed
	// SET routed to a different replica is still rejected (the receiver fails
	// CLOSED on any MarkSeen error). SetNX is master-pinned, so replica lag
	// can't let a replay slip. Falls back to per-pod memory single-replica.
	var jti security.JTIReplayStore = defaultimpl.NewMemoryJTIReplayStore()
	if rdb != nil {
		jti = redisbackend.NewJTIReplayStore(rdb)
	}

	rcv, err := caep.NewReceiver(cfg.Audience, jti, revoker, userProvider, transmitters, caepReceiverOptions(cfg, recorder, metricsReg, logger)...)
	if err != nil {
		return nil, err
	}
	return sso.WithCAEPReceiver(rcv), nil
}

// buildCAEPTransmitters loads + validates each trusted transmitter's trust
// bundle. Fails loud on a missing issuer/jwks_file, an unparseable bundle, a
// bad subject_mode, or iss_sub without an operator-pinned provider.
func buildCAEPTransmitters(in []config.CAEPTransmitterConfig) ([]caep.TrustedTransmitter, error) {
	transmitters := make([]caep.TrustedTransmitter, 0, len(in))
	for i, tt := range in {
		if tt.Issuer == "" {
			return nil, fmt.Errorf("caep.receiver.transmitters[%d].issuer required", i)
		}
		if tt.JWKSFile == "" {
			return nil, fmt.Errorf("caep.receiver.transmitters[%d].jwks_file required", i)
		}
		doc, err := os.ReadFile(tt.JWKSFile)
		if err != nil {
			return nil, fmt.Errorf("read caep.receiver.transmitters[%d].jwks_file: %w", i, err)
		}
		source, err := security.ParseStaticJWKS(doc)
		if err != nil {
			return nil, fmt.Errorf("parse caep.receiver.transmitters[%d] trust bundle: %w", i, err)
		}
		mode, err := CaepSubjectMode(tt.SubjectMode)
		if err != nil {
			return nil, err
		}
		// iss_sub mode REQUIRES an operator-pinned provider. An empty provider
		// is insecure: the local-subject lookup would otherwise fall back to
		// the SET's attacker-controlled sub_id.iss, letting a trusted
		// transmitter revoke users federated from ANY other provider
		// (cross-IdP subject hijack). NewReceiver enforces this too; we fail
		// here first to name the exact knob.
		if mode == caep.SubjectMapIssSub && strings.TrimSpace(tt.Provider) == "" {
			return nil, fmt.Errorf("caep.receiver.transmitters[%d].provider required when subject_mode is iss_sub (the provider MUST be operator-pinned to this transmitter's federated namespace; an empty provider is insecure)", i)
		}
		transmitters = append(transmitters, caep.TrustedTransmitter{
			Issuer:        tt.Issuer,
			JWKS:          source,
			SubjectMode:   mode,
			Provider:      tt.Provider,
			AllowedEvents: tt.AllowedEvents,
			AllowedAlgs:   tt.AllowedAlgs,
		})
	}
	return transmitters, nil
}

// caepReceiverOptions assembles the CAEP receiver options (audit recorder,
// logger, optional clock skew + metrics callback).
func caepReceiverOptions(cfg config.CAEPReceiverConfig, recorder *audit.Recorder, metricsReg *metrics.Metrics, logger spi.Logger) []caep.ReceiverOption {
	ropts := []caep.ReceiverOption{
		caep.WithReceiverAuditRecorder(recorder),
		caep.WithReceiverLogger(logger),
	}
	if cfg.MaxClockSkew > 0 {
		ropts = append(ropts, caep.WithReceiverMaxClockSkew(cfg.MaxClockSkew))
	}
	if metricsReg != nil {
		ropts = append(ropts, caep.WithReceiverMetric(func(outcome string) {
			metricsReg.SSFSetsReceivedTotal.WithLabelValues(outcome).Inc()
		}))
	}
	return ropts
}
