package config

import "time"

type RegistryConfig struct {
	Backend        string        `yaml:"backend"` // "memory" | "etcd"
	ServiceID      string        `yaml:"service_id"`
	ServiceAddress string        `yaml:"service_address"`
	ServiceTags    []string      `yaml:"service_tags"`
	ServiceTTL     time.Duration `yaml:"service_ttl"`

	EtcdEndpoints   []string      `yaml:"etcd_endpoints"`
	EtcdPrefix      string        `yaml:"etcd_prefix"`
	EtcdDialTimeout time.Duration `yaml:"etcd_dial_timeout"`
	EtcdUsername    string        `yaml:"etcd_username"`
	EtcdPassword    string        `yaml:"etcd_password"`
}

// WebAuthnConfig opts into CTAP/FIDO2 ceremony endpoints
// (/webauthn/{registration,login}/{begin,finish}). Without Enabled
// the routes aren't mounted and the subsystem is dark — no goroutines,
// no DB, no transitive go-webauthn dependency at runtime.
//
// RPID must be the registrable domain suffix of the origin the user
// agent will report (e.g. "example.com" for an SSO server at
// sso.example.com). RPOrigins MUST be fully qualified including the
// scheme. Misconfiguring either breaks attestation verification at
// finish time.
//
// Storage chooses where credentials + ceremony sessions live. memory
// is single-replica only; sqlite shares both across the cluster.
// Sessions and credentials use independent DSNs so operators can
// retain a short-lived in-memory session store while still persisting
// credentials.
type WebAuthnConfig struct {
	Enabled       bool                  `yaml:"enabled"`
	RPID          string                `yaml:"rp_id"`
	RPDisplayName string                `yaml:"rp_display_name"`
	RPOrigins     []string              `yaml:"rp_origins"`
	SessionTTL    time.Duration         `yaml:"session_ttl"`
	Storage       WebAuthnStorageConfig `yaml:"storage"`

	// RequireUserVerification makes the primary-login WebAuthn ceremony
	// demand user verification (PIN/biometric), not just user presence (a
	// tap). Default false leaves the library at its zero value (UV not
	// enforced) — byte-identical to a pre-fix build. The WebAuthn MFA
	// step-up factor ALWAYS requires user verification regardless of this
	// flag (a second factor must verify the user).
	RequireUserVerification bool `yaml:"require_user_verification"`

	// Attestation opts into the WebAuthn attestation policy: a
	// configurable conveyance preference + an operator AAGUID
	// allowlist/denylist gating which authenticators may register. The
	// zero value (conveyance ""/"none", policy mode "") is byte-identical
	// to a pre-policy build: no attestation requested, no AAGUID gating
	// (today's "any authenticator" behavior).
	Attestation WebAuthnAttestationConfig `yaml:"attestation"`

	// PrimaryAuthEnabled opts into passwordless passkey PRIMARY login: a
	// discoverable-credential (resident key) WebAuthn ceremony registered as
	// a full core.Authenticator under provider="webauthn" at /auth/login —
	// the user identifies by presenting their passkey, with no separate
	// password step. This is entirely ADDITIVE: it does not replace or
	// disable the existing WebAuthn-as-second-factor (step-up MFA) ceremony,
	// which keeps working unchanged, and it shares the SAME Helper (and
	// therefore the same enrolled credentials + RP config) as that step-up
	// path and the standalone /webauthn/login/conditional/{begin,finish}
	// ceremony endpoints. Default false: the "webauthn" primary authenticator
	// is not registered and /auth/login behaves byte-identically to a build
	// without this flag. Requires Enabled=true (the WebAuthn subsystem must
	// be on) — ignored otherwise.
	PrimaryAuthEnabled bool `yaml:"primary_auth_enabled"`

	// RequestCredProps opts into requesting the credProps extension at
	// registration, so the self-service passkey listing can report whether
	// each credential is discoverable (see core.MFAEnrolledFactor.Discoverable).
	// Pure metadata — no security decision changes. Default false —
	// byte-identical (no extensions key sent).
	RequestCredProps bool `yaml:"request_cred_props"`

	// RequestLargeBlobSupport opts into requesting largeBlob support
	// DETECTION (not use) at registration. Default false — byte-identical.
	RequestLargeBlobSupport bool `yaml:"request_large_blob_support"`

	// PasskeyPolicy opts into the require-passkey enrollment-nudge policy: a
	// non-blocking, advisory signal added to a successful /auth/login
	// response when the authenticated user has not yet registered a passkey.
	// See PasskeyPolicyConfig; the zero value (RequirePasskey false) is
	// byte-identical to a build without this feature.
	PasskeyPolicy PasskeyPolicyConfig `yaml:"passkey_policy"`
}

// PasskeyPolicyConfig configures the require-passkey enrollment-nudge policy
// (domains/authenticators/passkeypolicy, sso.WithPasskeyPolicy). It NEVER
// blocks or degrades login — a login that would qualify for the nudge still
// mints tokens normally; the nudge is an EXTRA advisory field the client UI
// may act on. Disabled by default (RequirePasskey false): an absent /
// zero-value section wires nothing, byte-identical to a build without this
// feature.
type PasskeyPolicyConfig struct {
	// RequirePasskey is the master switch. Requires webauthn.enabled=true
	// (cmd fails loud at boot otherwise — nothing could ever register a
	// passkey for the nudge to eventually satisfy).
	RequirePasskey bool `yaml:"require_passkey"`

	// PromptFrequency tunes the nudge cadence once RequirePasskey is on:
	// "never" (suppress the nudge outright — stage the policy before turning
	// on the UX prompt), "once" (default: nudge every login while the user
	// has no passkey), or "periodic" (additionally consult the wired
	// trust.TrustScorer, sso.WithTrustScorer — a low-risk login is throttled,
	// a high-risk login always nudges; no scorer wired, or a scoring error,
	// degrades to "once" behavior — fail-open toward MORE nudging, never
	// toward blocking the login). An empty value defaults to "once"; any
	// OTHER unrecognized value fails loud at boot (a typo must not silently
	// misbehave). See domains/authenticators/passkeypolicy's package doc for
	// the PRECISION NOTE on how "has a passkey" is currently determined
	// (this build has no credProps/discoverable-credential capture, so the
	// check is coarser than the field name implies: any registered WebAuthn
	// credential counts, not only a discoverable/resident-key one).
	PromptFrequency string `yaml:"passkey_prompt_frequency"`

	// RecoveryAllowed is advisory metadata echoed alongside the nudge signal
	// so client UI knows whether to also offer a "lost your passkey?"
	// affordance. This config enforces no recovery flow itself — the
	// recommended recovery path is the EXISTING self-service recovery-code
	// (surfaced at login as the MFA "recovery" method) followed by WebAuthn
	// re-registration (POST /me/mfa/webauthn/{begin,finish}); see
	// domains/authenticators/passkeypolicy's package doc for the
	// passwordless-only gap that reuse does NOT close.
	RecoveryAllowed bool `yaml:"passkey_recovery_allowed"`
}

// WebAuthnAttestationConfig configures authenticator attestation for
// WebAuthn registration. It lets a high-assurance operator restrict
// registration to approved authenticator models by AAGUID, instead of the
// default conveyance "none" that accepts ANY authenticator (including
// software / virtual ones).
//
// ASSURANCE LEVEL (be precise — do not over-claim):
//
// When a policy is ACTIVE it requires Conveyance "direct" (or "enterprise");
// the cmd + webauthn.NewHelper fail loud otherwise, because under none/
// indirect an authenticator may convey no attestation and report the all-zero
// AAGUID a denylist can never match. With a verified statement go-webauthn
// VERIFIES THE ATTESTATION SIGNATURE at finish time (the per-format
// packed/tpm/android-key/... verifier), and a credential that conveyed NO
// attestation (format "none" — which go-webauthn accepts with ZERO signature
// check) is REJECTED by the gate, closing the downgrade where a client ignores
// the requested conveyance.
//
// Wire MDS (the mds block below) for full adversary-resistance: with a FIDO
// Metadata Service source configured, go-webauthn validates the attestation
// certificate CHAIN up to the FIDO root, so a crafted self-signed x5c (or a
// self/none attestation) asserting an allowlisted AAGUID is REJECTED (its
// chain doesn't root in the MDS). WITHOUT an MDS source (the default,
// Config.MDS nil) the AAGUID gate is NOT cryptographically adversary-resistant
// — it is an OPERATIONAL control that gates honest clients, blocks
// non-attesting software authenticators, and gives audit visibility of which
// AAGUIDs registered, but is NOT a defense against a hostile registrant.
type WebAuthnAttestationConfig struct {
	// Conveyance is the attestation conveyance preference sent at
	// registration: ""/"none" (default — no attestation requested,
	// byte-identical to today), "indirect", "direct", or "enterprise".
	// When PolicyMode gates, this MUST be "direct" or "enterprise" (boot
	// fails otherwise) so the authenticator conveys a verified, model-specific
	// AAGUID; under none/indirect most authenticators report the zero AAGUID,
	// which an allowlist rejects and a denylist can never match.
	Conveyance string `yaml:"conveyance"`

	// PolicyMode selects AAGUID gating: ""/"off" (no gating — default),
	// "allowlist" (only AAGUIDs is permitted), or "denylist" (only
	// AAGUIDs is rejected). Allowlist + denylist are mutually exclusive. An
	// active mode requires Conveyance direct|enterprise (see above) and
	// rejects any credential that conveyed no attestation (format "none").
	PolicyMode string `yaml:"policy_mode"`

	// AAGUIDs is the allowlist / denylist of authenticator AAGUIDs (canonical
	// UUID strings like "ee882879-721c-4913-9775-3dfcce97072a", any case;
	// the bare 32-hex form is also accepted). Required + non-empty when
	// PolicyMode gates. Under allowlist, include the all-zero AAGUID
	// ("00000000-0000-0000-0000-000000000000") explicitly to admit
	// self-attestation / no-attestation authenticators — otherwise they
	// are rejected.
	AAGUIDs []string `yaml:"aaguids"`

	// MDS opts into FIDO Metadata Service root validation. When a source is
	// configured, the AAGUID gate becomes ADVERSARY-RESISTANT: go-webauthn
	// validates the attestation certificate chain to the FIDO root, so a
	// crafted self-signed x5c asserting an allowlisted AAGUID is rejected.
	// The zero value (no source) leaves Config.MDS nil — the operational
	// control described above, byte-identical to a pre-MDS build.
	MDS WebAuthnMDSConfig `yaml:"mds"`
}

// WebAuthnMDSConfig configures the FIDO Metadata Service (MDS) source that
// makes the WebAuthn attestation AAGUID gate adversary-resistant. The blob
// is the JWS an operator downloads from https://mds3.fido2.org/ (or fetches
// over HTTPS); go-webauthn JWS-verifies its signing chain to the built-in
// FIDO production root (or CustomRootFile for a test/non-prod MDS) at boot —
// a tampered / wrong-root blob FAILS LOUD rather than silently downgrading
// to no-MDS.
//
// EXACTLY ONE of File / FetchURL supplies the blob. Both empty ⇒ MDS off
// (Config.MDS nil, byte-identical default).
//
// REFRESH: the loaded metadata is a STARTUP SNAPSHOT — the in-memory
// provider does not refresh. The FIDO MDS rotates roughly monthly (the blob
// carries a nextUpdate date); reload by restarting with a fresh blob.
// go-webauthn's providers/cached fetch+refresh provider is the auto-refresh
// alternative (an out-of-band enhancement; cmd wires the snapshot provider).
type WebAuthnMDSConfig struct {
	// File is a path to the FIDO MDS blob on disk. Mutually exclusive with
	// FetchURL.
	File string `yaml:"file"`

	// FetchURL is an HTTPS URL the blob is fetched from at boot (dep-free
	// net/http). Mutually exclusive with File; must be https.
	FetchURL string `yaml:"fetch_url"`

	// CustomRootFile is a path to a file containing the base64 DER of a custom
	// root certificate (the raw x5c-style base64 body, NOT PEM armour) used to
	// verify the blob INSTEAD of the built-in FIDO production root. ONLY for a
	// non-production / test MDS (e.g. the FIDO conformance suite). Production
	// leaves it empty so the real FIDO root validates the blob.
	CustomRootFile string `yaml:"custom_root_file"`

	// FetchTimeout bounds the boot-time HTTPS fetch (FetchURL only). Zero
	// defaults to 30s.
	FetchTimeout time.Duration `yaml:"fetch_timeout"`
}

// WebAuthnStorageConfig selects the substrate for the WebAuthn
// UserStore + SessionStore. Both default to memory; operators
// running multi-replica turn on sqlite for each (independent DSNs
// so a fast-disk credential store can coexist with an in-memory
// session store on the same host).
type WebAuthnStorageConfig struct {
	Users    WebAuthnBackendConfig `yaml:"users"`
	Sessions WebAuthnBackendConfig `yaml:"sessions"`
}

// WebAuthnBackendConfig is the memory|sqlite selector + DSN for a
// single WebAuthn store.
type WebAuthnBackendConfig struct {
	// Backend: memory | sqlite | postgres (users only — durable passkey
	// credentials on the shared db-cluster) | redis (sessions only — the
	// hot ceremony-challenge store on the shared cluster). On a multi-replica
	// deployment users MUST be postgres and sessions MUST be redis, else
	// per-pod state breaks passkey login/registration under a no-affinity LB.
	Backend string                      `yaml:"backend"`
	SQLite  WebAuthnBackendSQLiteConfig `yaml:"sqlite"`
}

type WebAuthnBackendSQLiteConfig struct {
	DSN string `yaml:"dsn"`
}

// IdentityConfig selects the substrate for User + Client persistence
// (the two long-lived identity-domain stores). Default memory keeps
// the simple-bootstrap story but loses every DCR-registered client
// and every password-authenticator user on restart. SQLite persists
// across restarts and (with shared DSN) across replicas via OS file
// locking.
//
// Independent of [OAuthConfig.Backend] — the two domains can be
// mixed (e.g. SQLite identity + memory OAuth state for low-traffic
// CLI deployments) by setting backends separately.
