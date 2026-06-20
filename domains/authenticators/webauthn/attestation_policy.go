package webauthn

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// AttestationPolicyMode selects how [AttestationPolicy.Check] gates a
// freshly-registered credential's AAGUID.
type AttestationPolicyMode string

const (
	// AttestationPolicyOff disables AAGUID gating entirely. This is the
	// zero value, so a zero AttestationPolicy (or a nil *AttestationPolicy)
	// admits every authenticator — byte-identical to a build that never
	// knew about attestation policy. Operators that want to keep today's
	// "any authenticator" behavior leave the policy unset.
	AttestationPolicyOff AttestationPolicyMode = ""

	// AttestationPolicyAllowlist admits ONLY the configured AAGUIDs. Any
	// authenticator whose AAGUID is not in the set — including the zero
	// AAGUID reported by self-attestation / no-attestation authenticators,
	// UNLESS the operator explicitly lists the zero AAGUID — is rejected.
	// This is the high-assurance posture: registration is restricted to a
	// curated list of approved authenticator models.
	AttestationPolicyAllowlist AttestationPolicyMode = "allowlist"

	// AttestationPolicyDenylist rejects ONLY the configured AAGUIDs and
	// admits everything else (including the zero AAGUID). Useful to ban a
	// specific compromised / disallowed authenticator model while keeping
	// the open-registration default for the rest.
	AttestationPolicyDenylist AttestationPolicyMode = "denylist"
)

// ZeroAAGUID is the canonical all-zero AAGUID string. Self-attestation and
// no-attestation authenticators (the common case under conveyance "none")
// report this value. Under [AttestationPolicyAllowlist] it is rejected
// unless the operator explicitly includes it in the allowlist; under
// [AttestationPolicyDenylist] it can be banned by listing it.
const ZeroAAGUID = "00000000-0000-0000-0000-000000000000"

// AttestationFormatNone is go-webauthn's attestation statement format
// identifier for a credential that conveyed NO attestation. go-webauthn's
// VerifyAttestation short-circuits this format with ZERO signature
// verification (it only checks the statement is absent), so the AAGUID such a
// credential carries is the all-zero / unverifiable value — untrustworthy by
// construction. An active [AttestationPolicy] rejects it (see
// [Helper.checkAttestationPolicy]) because a denylist would never match its
// zero AAGUID (silent bypass) and an allowlist gate is meaningless on an
// un-attested AAGUID; a client may downgrade to this format even when the RP
// requested "direct" conveyance (conveyance is only a preference). Matched
// case-insensitively against gw.Credential.AttestationFormat.
const AttestationFormatNone = "none"

// ErrAttestationDenied is the sentinel returned by [AttestationPolicy.Check]
// (and surfaced by [Helper.FinishRegistration]) when an authenticator's
// AAGUID is not permitted by the configured policy. Callers map it to a
// clear registration-failure response; the AAGUID + the specific reason go
// to the audit trail, never to the registering client (oracle-reasonable:
// the user learns their authenticator isn't approved, not the policy
// internals).
var ErrAttestationDenied = errors.New("webauthn: authenticator not permitted by attestation policy")

// AttestationDeniedError is the concrete denial [Helper.FinishRegistration]
// returns when the attestation policy rejects a credential. It carries the
// canonical AAGUID + the policy mode + a machine-readable Reason so the wiring
// layer can emit a precise audit event (the AAGUID is a public
// authenticator-model identifier, not a secret — safe in audit metadata). It
// wraps [ErrAttestationDenied] so callers can match with errors.Is without
// depending on the concrete type.
type AttestationDeniedError struct {
	// AAGUID is the canonical (lowercased, hyphenated) AAGUID of the
	// rejected authenticator, or "" when the AAGUID was unparseable / the
	// credential conveyed no attestation.
	AAGUID string
	// Mode is the policy mode that produced the denial (allowlist|denylist).
	Mode AttestationPolicyMode
	// Reason is a stable, machine-readable denial reason for the audit trail
	// ([ReasonAAGUIDNotPermitted] for an AAGUID-list miss, or
	// [ReasonAttestationFormatNone] for a none-attestation downgrade). It is
	// an internal audit field, NOT a wire error code — the client always sees
	// the generic attestation_denied disposition regardless of Reason.
	Reason string
}

// Denial reasons carried on [AttestationDeniedError.Reason]. These are
// internal audit-metadata values (not wire error codes); the registering
// client never sees them — the oracle-safe attestation_denied disposition is
// identical for both.
const (
	// ReasonAAGUIDNotPermitted: the credential's AAGUID failed the
	// allowlist/denylist gate.
	ReasonAAGUIDNotPermitted = "aaguid_not_permitted"
	// ReasonAttestationFormatNone: the credential conveyed no attestation
	// (format "none"), so its AAGUID is untrustworthy and an active policy
	// rejects it before the AAGUID gate even runs.
	ReasonAttestationFormatNone = "attestation_format_none"
)

func (e *AttestationDeniedError) Error() string {
	if e.Reason == ReasonAttestationFormatNone {
		return fmt.Sprintf("webauthn: credential conveyed no attestation (format none) — rejected by active %s attestation policy", e.Mode)
	}
	return fmt.Sprintf("webauthn: authenticator AAGUID %q denied by %s attestation policy", e.AAGUID, e.Mode)
}

func (e *AttestationDeniedError) Unwrap() error { return ErrAttestationDenied }

// AttestationPolicy gates WebAuthn registration on the credential's AAGUID
// (the public authenticator-model identifier the authenticator embeds in
// attested credential data). It is operator-configured and applied at
// [Helper.FinishRegistration] AFTER go-webauthn has verified the attestation
// statement, so the AAGUID it gates on is the attestation-verified value.
//
// ASSURANCE — read carefully, do not over-claim:
//
//   - An ACTIVE policy requires conveyance direct|enterprise ([NewHelper]
//     enforces it) AND rejects any credential that conveyed NO attestation
//     (format "none" — go-webauthn accepts that format with ZERO signature
//     verification, so its AAGUID is untrustworthy). So with a policy active,
//     a credential MUST carry an attestation statement go-webauthn verified;
//     in the basic/x5c path go-webauthn matches the AAGUID to the attestation
//     certificate.
//
//   - WITH go-webauthn's metadata.Provider wired (webauthn.Config.MDS, built
//     from a FIDO MDS blob via BuildMDSProvider), the AAGUID gate becomes
//     ADVERSARY-RESISTANT: go-webauthn's VerifyAttestation validates the
//     attestation certificate CHAIN to the FIDO root and rejects an AAGUID
//     with no FIDO-root-validated metadata entry, so a crafted self-signed
//     x5c asserting an allowlisted AAGUID is rejected (its chain doesn't root
//     in the MDS). This closes the residual spoof below.
//
//   - WITHOUT the metadata.Provider (Config.MDS nil — the default), validating
//     that attestation certificate CHAIN to a FIDO Metadata Service root does
//     NOT happen, so the AAGUID gate is NOT adversary-resistant: a determined
//     attacker can craft a self-signed x5c (or self/none attestation)
//     asserting an allowlisted AAGUID. Without MDS this is therefore an
//     OPERATIONAL control (honest-client gating + audit visibility of
//     registered AAGUIDs + blocking non-attesting software authenticators),
//     NOT a defense against a hostile registrant. Wire MDS for full
//     adversary-resistance.
//
// The zero value (Mode == [AttestationPolicyOff]) admits every authenticator,
// so a Helper without a policy behaves byte-identically to one that never
// knew about attestation policy.
type AttestationPolicy struct {
	// Mode selects off / allowlist / denylist gating. Allowlist and
	// denylist are mutually exclusive by construction — a policy is built
	// from exactly one set of AAGUIDs via [NewAttestationPolicy].
	Mode AttestationPolicyMode

	// aaguids is the canonical (lowercased, hyphenated) AAGUID set the
	// mode gates against. Unexported so the only way to populate it is
	// through [NewAttestationPolicy], which canonicalizes every entry —
	// guaranteeing the lookup in Check compares like-for-like and a
	// config-supplied "EE882879-721C-..." matches a raw-16-byte AAGUID.
	aaguids map[string]struct{}
}

// NewAttestationPolicy builds a policy from a mode + a list of AAGUID
// strings (any mix of canonical "ee88..." UUIDs, uppercase, or
// hyphen-normalized variants — every entry is canonicalized). It validates
// that allowlist/denylist modes carry at least one AAGUID and that every
// AAGUID parses, so a typo in config fails loud at boot rather than
// silently admitting/denying the wrong authenticator.
//
// Mode off ignores the AAGUID list and yields a no-op policy (Check always
// returns nil) — the byte-identical default.
func NewAttestationPolicy(mode AttestationPolicyMode, aaguids []string) (*AttestationPolicy, error) {
	switch mode {
	case AttestationPolicyOff:
		return &AttestationPolicy{Mode: AttestationPolicyOff}, nil
	case AttestationPolicyAllowlist, AttestationPolicyDenylist:
		// fall through to the populated-set path
	default:
		return nil, fmt.Errorf("webauthn: unknown attestation policy mode %q (want off|allowlist|denylist)", mode)
	}
	if len(aaguids) == 0 {
		return nil, fmt.Errorf("webauthn: attestation policy mode %q requires at least one AAGUID", mode)
	}
	set := make(map[string]struct{}, len(aaguids))
	for _, raw := range aaguids {
		canon, err := CanonicalAAGUID(raw)
		if err != nil {
			return nil, fmt.Errorf("webauthn: attestation policy AAGUID %q: %w", raw, err)
		}
		set[canon] = struct{}{}
	}
	return &AttestationPolicy{Mode: mode, aaguids: set}, nil
}

// Check applies the policy to a 16-byte raw AAGUID (exactly the
// cred.Authenticator.AAGUID go-webauthn returns from the attestation's
// authenticator data). It returns nil when the authenticator is permitted
// and [ErrAttestationDenied] otherwise. A nil policy, or one in mode off,
// always permits — so the gate is byte-identical to today's behavior when
// unconfigured.
//
// allowlist: permit iff the canonical AAGUID is in the set. The zero AAGUID
// is NOT special-cased — it is rejected unless the operator explicitly
// allowlisted it (an unattested authenticator is, by definition, not an
// approved model). This is the deliberate opposite of go-webauthn's own
// FilteringConfig.PermittedAAGUIDs, which never excludes the zero AAGUID;
// here the high-assurance intent is to keep software/virtual authenticators
// out, so the zero AAGUID must be opted in.
//
// denylist: reject iff the canonical AAGUID is in the set; permit everything
// else (including the zero AAGUID, unless it is itself listed).
func (p *AttestationPolicy) Check(rawAAGUID []byte) error {
	if p == nil || p.Mode == AttestationPolicyOff {
		return nil
	}
	canon, err := canonicalAAGUIDFromBytes(rawAAGUID)
	if err != nil {
		// A non-16-byte AAGUID can't be matched against the canonical set.
		// Under allowlist that means "not approved" (reject — fail closed);
		// under denylist it can't match a denied entry so it is permitted.
		// Either way, surface a denial only for allowlist so a malformed
		// AAGUID never silently passes a restrictive policy.
		if p.Mode == AttestationPolicyAllowlist {
			return fmt.Errorf("%w: unparseable AAGUID", ErrAttestationDenied)
		}
		return nil
	}
	_, listed := p.aaguids[canon]
	switch p.Mode {
	case AttestationPolicyAllowlist:
		if !listed {
			return ErrAttestationDenied
		}
		return nil
	case AttestationPolicyDenylist:
		if listed {
			return ErrAttestationDenied
		}
		return nil
	default:
		return nil
	}
}

// Enabled reports whether the policy actually gates (mode != off). Used by
// the wiring layer to decide whether to emit the "attestation policy active"
// startup signal + to skip the per-finish canonicalization when off.
func (p *AttestationPolicy) Enabled() bool {
	return p != nil && p.Mode != AttestationPolicyOff
}

// CredentialAAGUID returns the canonical (lowercased, hyphenated) AAGUID of
// a registered credential, or "" when the AAGUID is absent / unparseable.
// Convenience for the wiring layer to surface the AAGUID in a success audit
// event (the public authenticator-model identifier operators curate their
// allowlist from). Takes the raw 16-byte AAGUID as carried on
// gw.Credential.Authenticator.AAGUID.
func CredentialAAGUID(rawAAGUID []byte) string {
	canon, err := canonicalAAGUIDFromBytes(rawAAGUID)
	if err != nil {
		return ""
	}
	return canon
}

// CanonicalAAGUID normalizes an AAGUID string (config form) to the canonical
// lowercased, hyphenated 8-4-4-4-12 UUID representation used for comparison.
// It accepts the standard hyphenated form ("ee882879-721c-4913-9775-3dfcce97072a")
// and the unhyphenated 32-hex-character form, in any case. Any other shape
// (wrong length, non-hex) errors — so a malformed config AAGUID fails loud.
//
// Implemented WITHOUT the github.com/google/uuid package on purpose: that
// dependency is only an indirect transitive of go-webauthn, and importing it
// directly here would promote it to a direct root dependency (changing
// go.mod). A 16-byte AAGUID is a fixed-width hex value, so canonicalization
// is a small, self-contained, allocation-light routine — and keeping the
// comparison logic in-tree makes the security-sensitive match auditable.
func CanonicalAAGUID(s string) (string, error) {
	b, err := aaguidStringToBytes(s)
	if err != nil {
		return "", err
	}
	return canonicalAAGUIDFromBytes(b)
}

// aaguidStringToBytes parses a config-supplied AAGUID string into its 16
// raw bytes. Accepts hyphenated (8-4-4-4-12) and bare-32-hex forms, any
// case. Hyphens are only permitted in the canonical positions so a
// mis-hyphenated string is rejected rather than silently accepted.
func aaguidStringToBytes(s string) ([]byte, error) {
	t := strings.TrimSpace(s)
	switch len(t) {
	case 32:
		// bare hex, no hyphens
	case 36:
		// hyphenated 8-4-4-4-12; hyphens must sit at 8,13,18,23
		if t[8] != '-' || t[13] != '-' || t[18] != '-' || t[23] != '-' {
			return nil, errors.New("hyphens not in canonical 8-4-4-4-12 positions")
		}
		t = t[:8] + t[9:13] + t[14:18] + t[19:23] + t[24:]
	default:
		return nil, fmt.Errorf("AAGUID must be 32 hex chars or a hyphenated UUID, got length %d", len(t))
	}
	b, err := hex.DecodeString(t)
	if err != nil {
		return nil, fmt.Errorf("AAGUID is not valid hex: %w", err)
	}
	if len(b) != 16 {
		return nil, fmt.Errorf("AAGUID decoded to %d bytes, want 16", len(b))
	}
	return b, nil
}

// canonicalAAGUIDFromBytes renders 16 raw AAGUID bytes as the canonical
// lowercased hyphenated UUID string. Rejects any other length so a
// truncated / over-long AAGUID can't masquerade as a valid one.
func canonicalAAGUIDFromBytes(b []byte) (string, error) {
	if len(b) != 16 {
		return "", fmt.Errorf("AAGUID must be 16 bytes, got %d", len(b))
	}
	const hexdigits = "0123456789abcdef"
	// 32 hex digits + 4 hyphens = 36 bytes.
	out := make([]byte, 0, 36)
	for i, x := range b {
		switch i {
		case 4, 6, 8, 10:
			out = append(out, '-')
		}
		out = append(out, hexdigits[x>>4], hexdigits[x&0x0f])
	}
	return string(out), nil
}
