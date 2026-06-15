package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/authenticators/webauthn"
	"github.com/snaplink/sso/oauth"
	"github.com/snaplink/sso/oidc"
	"github.com/snaplink/sso/spi"

	webauthnsqlite "github.com/snaplink/sso/authenticators/webauthn/sqlite"
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/metrics"
	"github.com/snaplink/sso/region"
)

func buildWebAuthnHelper(cfg config.WebAuthnConfig, logger spi.Logger) (*webauthn.Helper, webauthn.UserStore, webauthn.SessionStore, error) {
	if !cfg.Enabled {
		return nil, nil, nil, nil
	}
	if cfg.RPID == "" {
		return nil, nil, nil, errors.New("webauthn.rp_id required when webauthn.enabled")
	}
	if len(cfg.RPOrigins) == 0 {
		return nil, nil, nil, errors.New("webauthn.rp_origins must list at least one origin")
	}
	users, userDesc, err := buildWebAuthnUserStore(cfg.Storage.Users)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("webauthn users: %w", err)
	}
	sessions, sessionDesc, err := buildWebAuthnSessionStore(cfg.Storage.Sessions)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("webauthn sessions: %w", err)
	}
	policy, err := buildWebAuthnAttestationPolicy(cfg.Attestation)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("webauthn attestation: %w", err)
	}
	// MDS root validation (opt-in). A configured source makes the AAGUID gate
	// adversary-resistant; a malformed/wrong-root blob fails loud HERE at boot
	// (BuildMDSProvider verifies the blob's JWS chain to the FIDO root). Nil
	// when no source is configured — byte-identical to the pre-MDS ceremony.
	mds, err := buildWebAuthnMDSProvider(cfg.Attestation.MDS)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("webauthn mds: %w", err)
	}
	h, err := webauthn.NewHelper(webauthn.Config{
		RPID:                  cfg.RPID,
		RPDisplayName:         cfg.RPDisplayName,
		RPOrigins:             cfg.RPOrigins,
		SessionTTL:            cfg.SessionTTL,
		AttestationConveyance: cfg.Attestation.Conveyance,
		AttestationPolicy:     policy,
		MDS:                   mds,
	}, users, sessions)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("webauthn helper: %w", err)
	}
	logger.Info("webauthn enabled",
		"rp_id", cfg.RPID,
		"origins", cfg.RPOrigins,
		"users", userDesc,
		"sessions", sessionDesc,
		"attestation_conveyance", conveyanceLabel(cfg.Attestation.Conveyance),
		"attestation_policy", attestationPolicyLabel(policy),
		"attestation_mds", mdsLabel(cfg.Attestation.MDS, mds),
	)
	return h, users, sessions, nil
}

// buildWebAuthnMDSProvider maps the YAML MDS block to a go-webauthn
// metadata.Provider, or nil when no source is configured (the byte-identical
// default — gw.Config.MDS stays nil). When configured it reads the optional
// custom root file then delegates to webauthn.BuildMDSProvider, which loads +
// JWS-verifies the blob against the FIDO root (or that custom root) and FAILS
// LOUD on a tampered / wrong-root / unreadable blob — we never silently run
// without MDS when the operator asked for it (that would downgrade the
// security control). The resulting provider is the in-memory startup snapshot
// (reload = restart; see config.WebAuthnMDSConfig).
func buildWebAuthnMDSProvider(cfg config.WebAuthnMDSConfig) (metadata.Provider, error) {
	src := webauthn.MDSSource{
		FilePath:     strings.TrimSpace(cfg.File),
		FetchURL:     strings.TrimSpace(cfg.FetchURL),
		FetchTimeout: cfg.FetchTimeout,
	}
	if !src.Configured() {
		// No source — MDS off. Validate that a stray custom_root_file wasn't
		// set on its own (a likely misconfiguration: the operator meant to
		// point at a blob too) so it fails loud rather than silently no-op.
		if strings.TrimSpace(cfg.CustomRootFile) != "" {
			return nil, errors.New("webauthn.attestation.mds.custom_root_file is set but neither file nor fetch_url is — configure an MDS blob source or remove the custom root")
		}
		return nil, nil
	}
	if root := strings.TrimSpace(cfg.CustomRootFile); root != "" {
		raw, err := os.ReadFile(root)
		if err != nil {
			return nil, fmt.Errorf("read custom_root_file %q: %w", root, err)
		}
		src.CustomRootPEM = strings.TrimSpace(string(raw))
		if src.CustomRootPEM == "" {
			return nil, fmt.Errorf("custom_root_file %q is empty", root)
		}
	}
	return webauthn.BuildMDSProvider(src)
}

// mdsLabel renders the MDS source for the startup log without leaking the
// blob contents — just which source (if any) was wired.
func mdsLabel(cfg config.WebAuthnMDSConfig, provider metadata.Provider) string {
	if provider == nil {
		return "off"
	}
	if strings.TrimSpace(cfg.File) != "" {
		return "file (adversary-resistant)"
	}
	return "fetch (adversary-resistant)"
}

// buildWebAuthnAttestationPolicy maps the YAML attestation block to a
// webauthn.AttestationPolicy. An empty / "off" mode yields a nil policy (no
// gating — byte-identical to a pre-policy build). A gating mode requires a
// non-empty AAGUID list AND a conveyance of direct|enterprise (an attestation
// policy on an un-attested AAGUID is meaningless — under none/indirect the
// authenticator may convey no attestation, reporting the zero AAGUID a
// denylist can never match). All three — unknown-mode, empty-list, and
// weak-conveyance — fail loud here at boot rather than silently admitting/
// denying the wrong set. (webauthn.NewHelper enforces the same conveyance
// guard for embedders not going through this cmd path; this is the earlier,
// config-knob-named message for the YAML operator.)
func buildWebAuthnAttestationPolicy(cfg config.WebAuthnAttestationConfig) (*webauthn.AttestationPolicy, error) {
	mode := webauthn.AttestationPolicyMode(strings.ToLower(strings.TrimSpace(cfg.PolicyMode)))
	switch mode {
	case webauthn.AttestationPolicyOff, "off":
		// "off" is the operator-friendly spelling of the empty/off mode;
		// both yield a nil policy so the gate is dark.
		return nil, nil
	case webauthn.AttestationPolicyAllowlist, webauthn.AttestationPolicyDenylist:
		if !conveyanceAttestsAAGUID(cfg.Conveyance) {
			return nil, fmt.Errorf(
				"webauthn.attestation.policy_mode %q requires webauthn.attestation.conveyance \"direct\" or \"enterprise\" "+
					"(got %q) — a %s on an un-attested AAGUID is meaningless: under none/indirect the authenticator "+
					"may report the zero AAGUID, silently neutering the policy",
				cfg.PolicyMode, conveyanceLabel(cfg.Conveyance), mode)
		}
		return webauthn.NewAttestationPolicy(mode, cfg.AAGUIDs)
	default:
		return nil, fmt.Errorf("unknown webauthn.attestation.policy_mode %q (want off|allowlist|denylist)", cfg.PolicyMode)
	}
}

// conveyanceAttestsAAGUID reports whether the configured conveyance asks the
// authenticator to actually convey an attestation statement — i.e. "direct"
// or "enterprise". ""/"none"/"indirect" do NOT (the authenticator may omit
// the statement and report the zero AAGUID), so they can't back an AAGUID
// policy. Unknown strings return false; webauthn.NewHelper rejects them as
// invalid conveyance separately, so this only gates the recognized values.
func conveyanceAttestsAAGUID(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "direct", "enterprise":
		return true
	default:
		return false
	}
}

// conveyanceLabel renders the configured conveyance for the startup log,
// normalizing the empty value to "none" for clarity.
func conveyanceLabel(s string) string {
	if v := strings.ToLower(strings.TrimSpace(s)); v != "" {
		return v
	}
	return "none"
}

// attestationPolicyLabel renders the policy mode for the startup log.
func attestationPolicyLabel(p *webauthn.AttestationPolicy) string {
	if !p.Enabled() {
		return "off"
	}
	return string(p.Mode)
}

func buildWebAuthnUserStore(cfg config.WebAuthnBackendConfig) (webauthn.UserStore, string, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		return webauthn.NewMemoryUserStore(), "memory (single-replica only)", nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, "", errors.New("webauthn.storage.users.sqlite.dsn required when backend=sqlite")
		}
		store, err := webauthnsqlite.NewUserStore(cfg.SQLite.DSN)
		if err != nil {
			return nil, "", err
		}
		return store, "sqlite (cluster-shared)", nil
	default:
		return nil, "", fmt.Errorf("unknown webauthn.storage.users.backend %q", cfg.Backend)
	}
}

func buildWebAuthnSessionStore(cfg config.WebAuthnBackendConfig) (webauthn.SessionStore, string, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		return webauthn.NewMemorySessionStore(), "memory (single-replica only)", nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, "", errors.New("webauthn.storage.sessions.sqlite.dsn required when backend=sqlite")
		}
		store, err := webauthnsqlite.NewSessionStore(cfg.SQLite.DSN)
		if err != nil {
			return nil, "", err
		}
		return store, "sqlite (cluster-shared)", nil
	default:
		return nil, "", fmt.Errorf("unknown webauthn.storage.sessions.backend %q", cfg.Backend)
	}
}

// WebAuthn ceremony endpoint paths. Public so embedders writing
// docs / client code can reference them.
const (
	pathWebAuthnRegistrationBegin  = "/webauthn/registration/begin"
	pathWebAuthnRegistrationFinish = "/webauthn/registration/finish"
	pathWebAuthnLoginBegin         = "/webauthn/login/begin"
	pathWebAuthnLoginFinish        = "/webauthn/login/finish"
)

// webauthnDeps bundles everything the ceremony handlers need.
// Helper drives the WebAuthn protocol; ClientStore + TokenIssuers
// are optional — when supplied, /webauthn/login/finish accepts a
// `client_id` query parameter and issues a token for the
// authenticated user against that client (turning WebAuthn into a
// real first-class login method instead of just credential
// verification).
//
// oauth.RefreshTokenStore + oidc.IDTokenIssuer are independently optional. When
// the resolved client's AllowedScopes contains `offline_access`
// AND a oauth.RefreshTokenStore is wired, the response carries a
// refresh_token. When the scopes contain `openid` AND an
// oidc.IDTokenIssuer is wired, the response carries an id_token. Either
// missing dep silently degrades to the next-lower disclosure (just
// like /auth/login when those backends aren't configured).
type webauthnDeps struct {
	Helper            *webauthn.Helper
	ClientStore       sso.ClientStore
	TokenIssuers      map[string]sso.TokenIssuer
	DefaultStrat      string
	RefreshTokenStore oauth.RefreshTokenStore
	RefreshTokenTTL   time.Duration
	IDTokenIssuer     oidc.IDTokenIssuer
	Metrics           *metrics.Metrics // nil-safe; emit only when present

	// AuditRecorder records the WebAuthn registration audit events:
	// webauthn_registered (success, carrying the AAGUID for operator
	// allowlist curation) and webauthn_attestation_denied (failure, when
	// the attestation policy rejects an authenticator). Nil-safe — when
	// unset (an embedder without an audit pipeline, or a pre-audit build)
	// no registration audit event is emitted, leaving the begin/finish
	// flow byte-identical to before. Set in main from a.recorder.
	AuditRecorder *audit.Recorder

	// IDTokenIssuerForClient selects the per-tenant id_token issuer so a
	// WebAuthn-minted id_token is signed with the same key as that
	// tenant's access + id tokens elsewhere (closing the last surface
	// that bypassed WithTenantTokenIssuer). Mirrors the server's
	// fail-closed selector: err != nil ⇒ a misconfigured/unregistered
	// tenant issuer; emit=false ⇒ the tenant strategy can't mint
	// id_tokens (omit, never sign with the shared key). Nil-safe: when
	// unset (embedders constructing webauthnDeps directly) the handler
	// falls back to IDTokenIssuer for byte-identical legacy behavior.
	// Set in mountWebAuthnRoutes from *sso.Server.
	IDTokenIssuerForClient func(c *sso.Client) (oidc.IDTokenIssuer, bool, error)

	// IssuerForClient selects the per-tenant ACCESS-token issuer so a
	// WebAuthn-minted access token is signed with the same key as that
	// tenant's tokens from /auth/login + /token + its WebAuthn id_token —
	// the symmetric finish to IDTokenIssuerForClient (without it a tenant
	// client's WebAuthn access token could land on a different key than its
	// id_token). Mirrors the server's resolution order (tenant → client
	// strategy → default) and fail-closed error. Nil-safe: when unset
	// (embedders constructing webauthnDeps directly) the handler falls back
	// to the TokenStrategy lookup below for byte-identical legacy behavior.
	// Set in mountWebAuthnRoutes from *sso.Server.
	IssuerForClient func(c *sso.Client) (string, sso.TokenIssuer, error)

	// EncryptIDToken routes a freshly-signed id_token through the
	// server's JWE response-encryption path (fail-closed: returns
	// ("", false) when the client opted into encryption but it
	// failed, so the caller omits the id_token rather than leaking
	// cleartext). Nil-safe: nil means no encryption layer wired, so
	// the signed token passes through. Set in mountWebAuthnRoutes.
	EncryptIDToken func(ctx context.Context, client *sso.Client, signed string) (string, bool)

	// RegionResolver + ResidencyDecision close the data-residency hole on the
	// WebAuthn LOGIN mint path. WebAuthn login mints tokens exactly like
	// /auth/login, but the ceremony is mounted as RAW http.HandlerFunc (no
	// core.HandlerContext), so the in-pipeline login residency gate
	// (residencyGateLogin, which reads the serving region the region
	// middleware stashes on the HandlerContext) never runs here. Without these
	// a region-constrained tenant's user could complete WebAuthn login from a
	// disallowed serving region and receive tokens, bypassing residency.
	//
	// RegionResolver resolves the serving region from the raw *http.Request
	// (the same resolver the region middleware uses); ResidencyDecision is the
	// server's context-free residency seam (*sso.Server.ResidencyDecision),
	// returning (wireCode, denied) for a tenant + serving region. Set in cmd
	// ONLY when a region resolver is configured. BOTH nil (the embedder /
	// no-region default) ⇒ NO residency check ⇒ byte-identical to a
	// pre-residency build (residency simply isn't enforced for WebAuthn).
	RegionResolver    region.Resolver
	ResidencyDecision func(ctx context.Context, tenantID string, servingRegion region.ID, isWrite bool) (string, bool)
}

// mountWebAuthnRoutes registers the four ceremony endpoints on the
// SSO router. Begin endpoints accept JSON {"username", "display_name"};
// Finish endpoints take session_id from the ?session_id= query
// parameter and the WebAuthn attestation/assertion response in the
// body (passed through to go-webauthn unchanged).
//
// All four endpoints return JSON. Failure shape mirrors the OAuth
// error envelope ({"error", "error_description"}) so client-side
// integration is consistent across SSO surfaces.
