// Package webauthn provides WebAuthn (CTAP/FIDO2) registration +
// authentication helpers backed by github.com/go-webauthn/webauthn.
//
// The package intentionally does NOT implement [sso.Authenticator] —
// the standard Authenticator interface is single-step (credential
// in, result out), while WebAuthn requires a four-call ceremony:
//
//	register: client → server (begin)  → challenge + session
//	         server → client (finish) → attestation → store cred
//	login:    client → server (begin)  → challenge + session
//	         server → client (finish) → assertion → AuthResult
//
// Operators wire four HTTP handlers (one per Begin* / Finish*
// method) onto their router; the SDK keeps the begin/finish layer
// transport-agnostic so an embedder using gRPC or a custom
// protocol gets the same building blocks.
//
// Storage is pluggable via [UserStore] and [SessionStore]
// interfaces. Memory implementations ship for tests + single-
// replica deployments; production multi-replica deployments wire
// custom stores (the same SQLite / Redis / etcd backends used by
// the other distributed primitives in this codebase).
package webauthn

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol"
	gw "github.com/go-webauthn/webauthn/webauthn"
)

// ErrUserUnknown signals that no user with the supplied name is
// enrolled. UserStore implementations return this from GetByName
// when the username is not found.
var ErrUserUnknown = errors.New("webauthn: user unknown")

// ErrSessionUnknown signals that no session with the supplied ID
// exists — either the ID was never issued or it has already been
// consumed by a prior Take.
var ErrSessionUnknown = errors.New("webauthn: session unknown")

// ErrSessionExpired signals that the session existed but its TTL
// has elapsed. Returned from Take when an expired session is
// looked up.
var ErrSessionExpired = errors.New("webauthn: session expired")

// ErrClonedAuthenticator signals that the assertion's signature counter
// did not advance past the stored value — the FIDO "cloned authenticator"
// signal (a second copy of the credential private key being used in
// parallel, e.g. an exfiltrated/duplicated credential). go-webauthn does
// NOT error on a counter regression: [gw.Authenticator.UpdateCounter] sets
// CloneWarning=true, leaves SignCount unchanged, and returns no error,
// leaving the disposition to the Relying Party. [Helper.FinishLogin] reads
// that flag and FAILS the ceremony with this error rather than re-persisting
// a credential a clone just used. The library exempts the all-zero-counter
// case (authData.signCount==0 AND stored==0), the common platform-passkey
// posture, so a genuine zero-counter authenticator never trips this; the
// flag is only set on a true non-zero regression. The wire collapses this
// to the same generic login failure as any other assertion error
// (anti-enumeration) — detail goes only to the audit/credential-health
// signal the wiring layer emits.
var ErrClonedAuthenticator = errors.New("webauthn: cloned authenticator detected (signature counter regression)")

// Helper bundles a configured [gw.WebAuthn] + the two stores. All
// four ceremony entry points (Begin/Finish × Register/Login) hang
// off this type.
type Helper struct {
	core       *gw.WebAuthn
	users      UserStore
	sessions   SessionStore
	sessionTTL time.Duration

	// ceremonyTimeout, when > 0, sets the timeout (in milliseconds) sent
	// to the browser in the PublicKeyCredential's timeout parameter. After
	// this duration the browser cancels the ceremony automatically. 0 = no
	// explicit timeout — the library default is used (backward compatible).
	// Recommended: 60 * time.Second.
	ceremonyTimeout time.Duration

	// conveyance, when non-empty, is passed to BeginRegistration as
	// gw.WithConveyancePreference so the authenticator is asked to
	// produce an attestation statement ("direct"/"enterprise") or a
	// privacy-preserving one ("indirect"). Empty (the default) requests
	// no attestation — byte-identical to the pre-policy ceremony.
	conveyance protocol.ConveyancePreference

	// attestationPolicy gates the registered credential's AAGUID at
	// FinishRegistration AFTER go-webauthn verifies the attestation
	// statement. Nil / mode-off ⇒ no gating (byte-identical default).
	attestationPolicy *AttestationPolicy

	// requireUserVerification, when true, sets the user-verification
	// requirement to "required" on every BeginLogin so go-webauthn's
	// validateLogin enforces the UV bit (PIN/biometric), not mere
	// user-presence (a tap). Without it the library leaves
	// session.UserVerification == "" and shouldVerifyUser is always
	// false — the UV bit is never checked. The [WebAuthnMFAProvider]
	// always forces this on (a second factor MUST verify the user); the
	// primary-login ceremony opts in via [Config.RequireUserVerification].
	requireUserVerification bool
}

// Config is the operator-supplied configuration. RPID is the
// Relying Party ID — should equal the registrable domain
// suffix of the origin the user-agent will report (e.g. "example.com"
// for an SSO server at sso.example.com). RPOrigins lists the
// allowed origins; production deployments MUST include the
// scheme (e.g. "https://sso.example.com").
type Config struct {
	RPID          string
	RPDisplayName string
	RPOrigins     []string
	SessionTTL    time.Duration

	// CeremonyTimeout is the timeout sent to the browser in the
	// PublicKeyCredential's timeout parameter (milliseconds). After this
	// duration the browser cancels the ceremony automatically. 0 = no
	// explicit timeout — the library default is used (backward compatible).
	// Recommended: 60 * time.Second.
	CeremonyTimeout time.Duration

	// AttestationConveyance sets the WebAuthn attestation conveyance
	// preference sent to the client at BeginRegistration. Accepts
	// ""/"none" (no attestation — the default, byte-identical to a
	// pre-policy build), "indirect", "direct", or "enterprise". A
	// non-none value asks the authenticator to convey an attestation
	// statement so the AAGUID it carries is attested (and, for "direct"/
	// "enterprise", the statement signature is verified by go-webauthn at
	// finish time). When an [AttestationPolicy] is active this MUST be
	// "direct" or "enterprise" — [NewHelper] FAILS otherwise, because under
	// none/indirect many authenticators omit the attestation statement and
	// report the zero AAGUID, which a denylist can never match (silent
	// bypass). Invalid values are rejected by [NewHelper].
	AttestationConveyance string

	// AttestationPolicy, when set to a gating mode, restricts which
	// authenticators may register by their AAGUID (allowlist / denylist),
	// applied at FinishRegistration. An active policy additionally rejects
	// any credential that conveyed no attestation (format "none") and
	// REQUIRES AttestationConveyance direct|enterprise. Nil ⇒ no gating (the
	// default — byte-identical to a pre-policy build).
	AttestationPolicy *AttestationPolicy

	// RequireUserVerification, when true, makes the primary-login ceremony
	// demand user verification (PIN/biometric), not just user presence (a
	// tap). It sets gw.Config.AuthenticatorSelection.UserVerification =
	// VerificationRequired AND passes the per-ceremony WithUserVerification
	// option at BeginLogin, so go-webauthn's validateLogin enforces the UV
	// bit. Default false leaves the library at its zero value (UV not
	// enforced) — byte-identical to a pre-fix build. NOTE: the WebAuthn MFA
	// step-up factor ([WebAuthnMFAProvider]) ALWAYS requires user
	// verification regardless of this flag — a real second factor must
	// verify the user, not merely confirm presence.
	RequireUserVerification bool

	// MDS, when non-nil, is a FIDO Metadata Service provider set as
	// gw.Config.MDS. With it, go-webauthn's VerifyAttestation validates the
	// attestation certificate CHAIN to the FIDO root (or the provider's
	// configured root) and rejects an authenticator whose AAGUID has no
	// FIDO-root-validated metadata entry — making the [AttestationPolicy]
	// AAGUID gate ADVERSARY-RESISTANT (a crafted self-signed x5c asserting an
	// allowlisted AAGUID is rejected because its chain doesn't root in the
	// MDS). Build one from a downloaded MDS blob via [BuildMDSProvider]
	// (the in-memory startup-snapshot provider) or pass any other
	// metadata.Provider (e.g. go-webauthn's providers/cached fetch+refresh
	// provider). Nil ⇒ no metadata validation — byte-identical to today; the
	// AttestationPolicy then remains the operational/honest-client control,
	// NOT a defence against a hostile registrant. MDS strengthens an
	// AttestationPolicy but does not require one (MDS alone makes go-webauthn
	// reject untrusted authenticators).
	MDS metadata.Provider
}

// NewHelper validates cfg + returns the helper. RPID + at least
// one RPOrigin are required.
func NewHelper(cfg Config, users UserStore, sessions SessionStore) (*Helper, error) {
	if cfg.RPID == "" {
		return nil, errors.New("webauthn: RPID required")
	}
	if len(cfg.RPOrigins) == 0 {
		return nil, errors.New("webauthn: at least one RPOrigin required")
	}
	if users == nil || sessions == nil {
		return nil, errors.New("webauthn: UserStore + SessionStore required")
	}
	conveyance, err := validateAttestationConveyance(cfg)
	if err != nil {
		return nil, err
	}
	core, err := gw.New(buildGWConfig(cfg))
	if err != nil {
		return nil, fmt.Errorf("webauthn: configure: %w", err)
	}
	ttl := cfg.SessionTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &Helper{
		core:                    core,
		users:                   users,
		sessions:                sessions,
		sessionTTL:              ttl,
		ceremonyTimeout:         cfg.CeremonyTimeout,
		conveyance:              conveyance,
		attestationPolicy:       cfg.AttestationPolicy,
		requireUserVerification: cfg.RequireUserVerification,
	}, nil
}

// validateAttestationConveyance maps the operator-supplied conveyance string to
// the go-webauthn protocol constant and enforces the boot guard: an ACTIVE
// attestation policy is meaningless unless the RP asks for attestation to be
// conveyed. Under conveyance ""/none/indirect most authenticators omit the
// attestation statement and report the all-zero AAGUID, which a denylist can
// never match (silent bypass) and an allowlist gate can only reject wholesale —
// so a policy with weak conveyance is silently ineffective. Require direct (or
// stronger: enterprise) so the gate sees a verified, model-specific AAGUID. Fail
// loud here rather than ship a dark policy. (mapConveyance has already validated
// the string; "" / PreferIndirectAttestation are the below-direct values.)
func validateAttestationConveyance(cfg Config) (protocol.ConveyancePreference, error) {
	conveyance, err := mapConveyance(cfg.AttestationConveyance)
	if err != nil {
		return "", err
	}
	if cfg.AttestationPolicy.Enabled() &&
		(conveyance == "" || conveyance == protocol.PreferIndirectAttestation) {
		return "", fmt.Errorf(
			"webauthn: attestation policy mode %q requires AttestationConveyance \"direct\" or \"enterprise\" "+
				"(got %q) — an attestation policy on an un-attested AAGUID is meaningless",
			cfg.AttestationPolicy.Mode, conveyanceOrNone(cfg.AttestationConveyance))
	}
	return conveyance, nil
}

// buildGWConfig assembles the core gw.Config from cfg. It mirrors the operator's
// MDS provider (nil ⇒ no metadata validation, byte-identical to the pre-MDS
// ceremony) and pins the user-verification requirement into the core config so
// the assertion options sent to the client AND go-webauthn's stored
// session.UserVerification both say "required" — without it validateLogin's
// shouldVerifyUser is always false and the UV bit goes unchecked (mere
// user-presence satisfies the ceremony). BeginLogin also passes the per-ceremony
// option as a belt-and-suspenders against a future library default change. Left
// at the zero value when the operator hasn't opted in — byte-identical to a
// pre-fix build.
func buildGWConfig(cfg Config) *gw.Config {
	gwCfg := &gw.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.RPOrigins,
		MDS:           cfg.MDS,
	}
	if cfg.RequireUserVerification {
		gwCfg.AuthenticatorSelection.UserVerification = protocol.VerificationRequired
	}
	return gwCfg
}

// mapConveyance validates + maps the operator-supplied conveyance string
// to the go-webauthn protocol constant. "" and "none" both map to the
// empty preference (no attestation requested — the default), so the
// BeginRegistration option is NOT passed and the wire is byte-identical to
// a pre-policy build. Any other unrecognized value is rejected so a typo
// in config fails loud at boot rather than silently disabling attestation.
func mapConveyance(s string) (protocol.ConveyancePreference, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none":
		// Empty sentinel: BeginRegistration leaves Attestation at the
		// library default ("none") and does not apply the option.
		return "", nil
	case "indirect":
		return protocol.PreferIndirectAttestation, nil
	case "direct":
		return protocol.PreferDirectAttestation, nil
	case "enterprise":
		return protocol.PreferEnterpriseAttestation, nil
	default:
		return "", fmt.Errorf("webauthn: unknown attestation conveyance %q (want none|indirect|direct|enterprise)", s)
	}
}

// conveyanceOrNone renders the operator-supplied conveyance string for the
// boot-guard error message, normalizing the empty value to "none" so the
// error names a concrete preference the operator can recognize in config.
func conveyanceOrNone(s string) string {
	if v := strings.ToLower(strings.TrimSpace(s)); v != "" {
		return v
	}
	return "none"
}

// BeginRegistration starts a registration ceremony for name. When
// the user doesn't exist yet, a fresh record is created with the
// supplied displayName. Returns the CredentialCreation options the
// client passes to navigator.credentials.create + an opaque
// sessionID the client echoes back at FinishRegistration time.
func (h *Helper) BeginRegistration(ctx context.Context, name, displayName string) (*protocol.CredentialCreation, string, error) {
	user, err := h.users.GetByName(ctx, name)
	if errors.Is(err, ErrUserUnknown) {
		user, err = h.users.CreateUser(ctx, name, displayName)
	}
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: load user: %w", err)
	}
	var opts []gw.RegistrationOption
	if h.conveyance != "" {
		// Ask the client for an attestation statement so the AAGUID the
		// authenticator reports at finish time is attested. Only applied
		// when a non-none conveyance was configured — otherwise no option
		// is passed and the creation options are byte-identical to today.
		opts = append(opts, gw.WithConveyancePreference(h.conveyance))
	}
	if h.ceremonyTimeout > 0 {
		timeoutMs := int(h.ceremonyTimeout.Milliseconds())
		opts = append(opts, func(cco *protocol.PublicKeyCredentialCreationOptions) {
			cco.Timeout = timeoutMs
		})
	}
	creation, session, err := h.core.BeginRegistration(user, opts...)
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: begin registration: %w", err)
	}
	sessionID, err := h.persistSession(ctx, session)
	if err != nil {
		return nil, "", err
	}
	return creation, sessionID, nil
}

// FinishRegistration completes the ceremony. session is the ID
// returned by the matching BeginRegistration; r is the request
// carrying the attestation response in its body.
func (h *Helper) FinishRegistration(ctx context.Context, sessionID string, r *http.Request) (*gw.Credential, error) {
	session, err := h.sessions.Take(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	user, err := h.userFromSession(ctx, session)
	if err != nil {
		return nil, err
	}
	cred, err := h.core.FinishRegistration(user, *session, r)
	if err != nil {
		return nil, fmt.Errorf("webauthn: finish registration: %w", err)
	}
	// Attestation-policy gate. Applied AFTER go-webauthn verified the
	// attestation statement (so cred.Authenticator.AAGUID is the
	// attestation-verified value) and BEFORE we persist — a denied
	// authenticator's credential is never written. Returns a typed
	// AttestationDeniedError carrying the canonical AAGUID so the wiring
	// layer can audit the denial precisely. Nil / mode-off ⇒ no gating.
	if err := h.checkAttestationPolicy(cred); err != nil {
		return nil, err
	}
	if err := h.users.AddCredential(ctx, user.Name, cred); err != nil {
		return nil, fmt.Errorf("webauthn: persist credential: %w", err)
	}
	return cred, nil
}

// BeginLogin starts an authentication ceremony for name. Returns
// the CredentialAssertion options + an opaque sessionID. When the
// Helper was built with RequireUserVerification, the assertion demands
// user verification (PIN/biometric).
func (h *Helper) BeginLogin(ctx context.Context, name string) (*protocol.CredentialAssertion, string, error) {
	return h.beginLogin(ctx, name, h.requireUserVerification)
}

// beginLogin is the shared entry point behind [Helper.BeginLogin] and the
// MFA provider's forced-UV ceremony. requireUV pins the assertion's
// user-verification requirement to "required" so go-webauthn's validateLogin
// enforces the UV bit; false leaves the library default. The MFA factor
// passes requireUV=true unconditionally — a second factor MUST verify the
// user, independent of the primary-login RequireUserVerification setting.
func (h *Helper) beginLogin(ctx context.Context, name string, requireUV bool) (*protocol.CredentialAssertion, string, error) {
	user, err := h.users.GetByName(ctx, name)
	if err != nil {
		return nil, "", err
	}
	var opts []gw.LoginOption
	if requireUV {
		// Belt-and-suspenders alongside the core-config AuthenticatorSelection:
		// pin UV on this ceremony's options + session so the stored
		// session.UserVerification is "required" regardless of any future
		// library default for AuthenticatorSelection.
		opts = append(opts, gw.WithUserVerification(protocol.VerificationRequired))
	}
	if h.ceremonyTimeout > 0 {
		timeoutMs := int(h.ceremonyTimeout.Milliseconds())
		opts = append(opts, func(cco *protocol.PublicKeyCredentialRequestOptions) {
			cco.Timeout = timeoutMs
		})
	}
	assertion, session, err := h.core.BeginLogin(user, opts...)
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: begin login: %w", err)
	}
	sessionID, err := h.persistSession(ctx, session)
	if err != nil {
		return nil, "", err
	}
	return assertion, sessionID, nil
}

// FinishLogin completes the authentication ceremony. The signed
// counter on the returned credential is updated in the user store
// so the next FinishLogin sees the new value.
//
// go-webauthn does NOT reject a signature-counter regression on its own:
// its validateLogin calls Authenticator.UpdateCounter, which on
// counter <= stored (and not the all-zero case) sets
// Authenticator.CloneWarning=true, leaves SignCount unchanged, and returns
// NO error — leaving the disposition to the Relying Party. This helper reads
// that flag and FAILS the ceremony with [ErrClonedAuthenticator] BEFORE
// persisting, so an assertion replayed/forged from a cloned or exfiltrated
// credential (counter <= stored) is rejected rather than silently accepted
// and re-persisted. The all-zero-counter platform-passkey case never trips
// the flag (the library exempts it), so this is safe for passkeys.
func (h *Helper) FinishLogin(ctx context.Context, sessionID string, r *http.Request) (*User, *gw.Credential, error) {
	session, err := h.sessions.Take(ctx, sessionID)
	if err != nil {
		return nil, nil, err
	}
	user, err := h.userFromSession(ctx, session)
	if err != nil {
		return nil, nil, err
	}
	cred, err := h.core.FinishLogin(user, *session, r)
	if err != nil {
		return nil, nil, fmt.Errorf("webauthn: finish login: %w", err)
	}
	// Cloned-authenticator gate. Reject (and DO NOT re-persist) when the
	// counter did not advance — the credential may be cloned. Returning before
	// UpdateCredential also avoids writing back the unchanged SignCount, which
	// would mask the regression on the next ceremony.
	if cred.Authenticator.CloneWarning {
		return nil, nil, ErrClonedAuthenticator
	}
	if err := h.users.UpdateCredential(ctx, user.Name, cred); err != nil {
		return nil, nil, fmt.Errorf("webauthn: persist updated credential: %w", err)
	}
	return user, cred, nil
}
