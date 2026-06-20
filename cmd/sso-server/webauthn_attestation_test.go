package main

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/domains/authenticators/webauthn"
	"github.com/snaplink/sso/platform/audit"

	gw "github.com/go-webauthn/webauthn/webauthn"
)

const testAAGUIDCanonical = "ee882879-721c-4913-9775-3dfcce97072a"

var testRawAAGUID = []byte{
	0xee, 0x88, 0x28, 0x79, 0x72, 0x1c, 0x49, 0x13,
	0x97, 0x75, 0x3d, 0xfc, 0xce, 0x97, 0x07, 0x2a,
}

func TestBuildWebAuthnAttestationPolicy(t *testing.T) {
	// off / empty → nil policy (no gating, byte-identical default).
	for _, mode := range []string{"", "off", "OFF", "  "} {
		p, err := buildWebAuthnAttestationPolicy(config.WebAuthnAttestationConfig{PolicyMode: mode})
		if err != nil {
			t.Fatalf("mode %q: %v", mode, err)
		}
		if p.Enabled() {
			t.Fatalf("mode %q must yield a non-gating policy", mode)
		}
	}

	// allowlist with AAGUIDs + direct conveyance builds an enabled policy.
	p, err := buildWebAuthnAttestationPolicy(config.WebAuthnAttestationConfig{
		Conveyance: "direct",
		PolicyMode: "allowlist",
		AAGUIDs:    []string{testAAGUIDCanonical},
	})
	if err != nil {
		t.Fatalf("allowlist: %v", err)
	}
	if !p.Enabled() || p.Mode != webauthn.AttestationPolicyAllowlist {
		t.Fatalf("allowlist policy not built correctly: %+v", p)
	}

	// denylist likewise (enterprise conveyance is also accepted — stronger
	// than direct).
	p, err = buildWebAuthnAttestationPolicy(config.WebAuthnAttestationConfig{
		Conveyance: "enterprise",
		PolicyMode: "DenyList",
		AAGUIDs:    []string{testAAGUIDCanonical},
	})
	if err != nil {
		t.Fatalf("denylist: %v", err)
	}
	if p.Mode != webauthn.AttestationPolicyDenylist {
		t.Fatalf("denylist mode = %q", p.Mode)
	}

	// An active policy with a below-direct conveyance ("" / none / indirect)
	// fails loud: the boot guard rejects a policy on an un-attested AAGUID.
	for _, conv := range []string{"", "none", "indirect"} {
		if _, err := buildWebAuthnAttestationPolicy(config.WebAuthnAttestationConfig{
			Conveyance: conv,
			PolicyMode: "allowlist",
			AAGUIDs:    []string{testAAGUIDCanonical},
		}); err == nil {
			t.Fatalf("allowlist with conveyance %q must error (policy needs direct|enterprise)", conv)
		}
		if _, err := buildWebAuthnAttestationPolicy(config.WebAuthnAttestationConfig{
			Conveyance: conv,
			PolicyMode: "denylist",
			AAGUIDs:    []string{testAAGUIDCanonical},
		}); err == nil {
			t.Fatalf("denylist with conveyance %q must error (policy needs direct|enterprise)", conv)
		}
	}

	// allowlist without AAGUIDs fails loud (even with a valid conveyance).
	if _, err := buildWebAuthnAttestationPolicy(config.WebAuthnAttestationConfig{
		Conveyance: "direct",
		PolicyMode: "allowlist",
	}); err == nil {
		t.Fatal("allowlist with no AAGUIDs must error")
	}

	// unknown mode fails loud.
	if _, err := buildWebAuthnAttestationPolicy(config.WebAuthnAttestationConfig{PolicyMode: "bogus"}); err == nil {
		t.Fatal("unknown mode must error")
	}

	// malformed AAGUID fails loud.
	if _, err := buildWebAuthnAttestationPolicy(config.WebAuthnAttestationConfig{
		Conveyance: "direct",
		PolicyMode: "allowlist",
		AAGUIDs:    []string{"not-a-uuid"},
	}); err == nil {
		t.Fatal("malformed AAGUID must error")
	}
}

func TestBuildWebAuthnHelper_AttestationConfigPlumbedThrough(t *testing.T) {
	// A valid attestation block builds the helper.
	h, _, _, err := buildWebAuthnHelper(config.WebAuthnConfig{
		Enabled:   true,
		RPID:      "example.com",
		RPOrigins: []string{"https://sso.example.com"},
		Attestation: config.WebAuthnAttestationConfig{
			Conveyance: "direct",
			PolicyMode: "allowlist",
			AAGUIDs:    []string{testAAGUIDCanonical},
		},
	}, quietLogger())
	if err != nil {
		t.Fatalf("buildWebAuthnHelper with attestation: %v", err)
	}
	if h == nil {
		t.Fatal("helper nil with valid attestation config")
	}

	// An invalid conveyance is rejected at build time.
	if _, _, _, err := buildWebAuthnHelper(config.WebAuthnConfig{
		Enabled:     true,
		RPID:        "example.com",
		RPOrigins:   []string{"https://sso.example.com"},
		Attestation: config.WebAuthnAttestationConfig{Conveyance: "bogus"},
	}, quietLogger()); err == nil {
		t.Fatal("invalid conveyance must error at build")
	}

	// An invalid policy is rejected at build time.
	if _, _, _, err := buildWebAuthnHelper(config.WebAuthnConfig{
		Enabled:     true,
		RPID:        "example.com",
		RPOrigins:   []string{"https://sso.example.com"},
		Attestation: config.WebAuthnAttestationConfig{PolicyMode: "allowlist"},
	}, quietLogger()); err == nil {
		t.Fatal("allowlist with no AAGUIDs must error at build")
	}
}

func TestBuildWebAuthnHelper_DefaultAttestationOff(t *testing.T) {
	// No attestation block ⇒ the helper builds exactly as before (the
	// default-off byte-identical path). buildWebAuthnAttestationPolicy
	// returns nil, so no policy is attached.
	h, _, _, err := buildWebAuthnHelper(config.WebAuthnConfig{
		Enabled:   true,
		RPID:      "example.com",
		RPOrigins: []string{"https://sso.example.com"},
	}, quietLogger())
	if err != nil {
		t.Fatalf("buildWebAuthnHelper: %v", err)
	}
	if h == nil {
		t.Fatal("helper nil")
	}
	p, err := buildWebAuthnAttestationPolicy(config.WebAuthnConfig{}.Attestation)
	if err != nil {
		t.Fatalf("default policy: %v", err)
	}
	if p != nil {
		t.Fatalf("default attestation must yield nil policy, got %+v", p)
	}
}

func TestHelperAttestationPolicyEnabled_GatesSuccessAudit(t *testing.T) {
	// The finish handler emits the success audit ONLY when the policy is
	// active. Prove the gate the handler keys off: a helper built with no
	// attestation block reports disabled (→ byte-identical, no success
	// audit); one with a policy reports enabled.
	off, _, _, err := buildWebAuthnHelper(config.WebAuthnConfig{
		Enabled:   true,
		RPID:      "example.com",
		RPOrigins: []string{"https://sso.example.com"},
	}, quietLogger())
	if err != nil {
		t.Fatalf("build off helper: %v", err)
	}
	if off.AttestationPolicyEnabled() {
		t.Fatal("helper without attestation policy must report disabled")
	}

	on, _, _, err := buildWebAuthnHelper(config.WebAuthnConfig{
		Enabled:   true,
		RPID:      "example.com",
		RPOrigins: []string{"https://sso.example.com"},
		Attestation: config.WebAuthnAttestationConfig{
			Conveyance: "direct", // required now that a policy is active
			PolicyMode: "allowlist",
			AAGUIDs:    []string{testAAGUIDCanonical},
		},
	}, quietLogger())
	if err != nil {
		t.Fatalf("build on helper: %v", err)
	}
	if !on.AttestationPolicyEnabled() {
		t.Fatal("helper with allowlist policy must report enabled")
	}
}

func TestRecordWebAuthnRegistered_EmitsAAGUID(t *testing.T) {
	sink := audit.NewMemorySink(8)
	deps := &webauthnDeps{AuditRecorder: audit.New(sink)}
	cred := &gw.Credential{ID: []byte("c1")}
	cred.Authenticator.AAGUID = testRawAAGUID

	r := httptest.NewRequest("POST", "/webauthn/registration/finish?session_id=s", nil)
	recordWebAuthnRegistered(deps, r, cred)

	events, _ := sink.Query(context.Background(), audit.Query{})
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	e := events[0]
	if e.Type != audit.EventWebAuthnRegistered {
		t.Fatalf("type = %q, want webauthn_registered", e.Type)
	}
	if e.Outcome != audit.OutcomeSuccess {
		t.Fatalf("outcome = %q, want success", e.Outcome)
	}
	if e.Metadata["aaguid"] != testAAGUIDCanonical {
		t.Fatalf("aaguid metadata = %q, want %q", e.Metadata["aaguid"], testAAGUIDCanonical)
	}
}

func TestRecordWebAuthnAttestationDenied_EmitsAAGUIDAndMode(t *testing.T) {
	sink := audit.NewMemorySink(8)
	deps := &webauthnDeps{AuditRecorder: audit.New(sink)}
	denied := &webauthn.AttestationDeniedError{
		AAGUID: testAAGUIDCanonical,
		Mode:   webauthn.AttestationPolicyAllowlist,
		Reason: webauthn.ReasonAAGUIDNotPermitted,
	}

	r := httptest.NewRequest("POST", "/webauthn/registration/finish?session_id=s", nil)
	recordWebAuthnAttestationDenied(deps, r, denied)

	events, _ := sink.Query(context.Background(), audit.Query{})
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	e := events[0]
	if e.Type != audit.EventWebAuthnAttestationDenied {
		t.Fatalf("type = %q, want webauthn_attestation_denied", e.Type)
	}
	if e.Outcome != audit.OutcomeFailure {
		t.Fatalf("outcome = %q, want failure", e.Outcome)
	}
	if e.Metadata["aaguid"] != testAAGUIDCanonical {
		t.Fatalf("aaguid = %q, want %q", e.Metadata["aaguid"], testAAGUIDCanonical)
	}
	if e.Metadata["policy_mode"] != "allowlist" {
		t.Fatalf("policy_mode = %q, want allowlist", e.Metadata["policy_mode"])
	}
	if e.Metadata["reason"] != webauthn.ReasonAAGUIDNotPermitted {
		t.Fatalf("reason metadata = %q, want %q", e.Metadata["reason"], webauthn.ReasonAAGUIDNotPermitted)
	}
	if e.Reason == "" {
		t.Fatal("reason must carry the operator-side detail")
	}
}

// TestRecordWebAuthnAttestationDenied_NoneReason proves the none-attestation
// downgrade surfaces its distinct reason (attestation_format_none) in the
// audit metadata, so an operator can see a downgrade attempt separately from
// an AAGUID-list miss.
func TestRecordWebAuthnAttestationDenied_NoneReason(t *testing.T) {
	sink := audit.NewMemorySink(8)
	deps := &webauthnDeps{AuditRecorder: audit.New(sink)}
	denied := &webauthn.AttestationDeniedError{
		Mode:   webauthn.AttestationPolicyDenylist,
		Reason: webauthn.ReasonAttestationFormatNone,
	}
	r := httptest.NewRequest("POST", "/webauthn/registration/finish?session_id=s", nil)
	recordWebAuthnAttestationDenied(deps, r, denied)

	events, _ := sink.Query(context.Background(), audit.Query{})
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	if events[0].Metadata["reason"] != webauthn.ReasonAttestationFormatNone {
		t.Fatalf("reason = %q, want %q", events[0].Metadata["reason"], webauthn.ReasonAttestationFormatNone)
	}
}

// TestRecordWebAuthn_NilRecorderSafe proves the audit emitters are no-ops
// when no recorder is wired (an embedder without an audit pipeline) — the
// default-off byte-identical path.
func TestRecordWebAuthn_NilRecorderSafe(t *testing.T) {
	deps := &webauthnDeps{} // no AuditRecorder
	r := httptest.NewRequest("POST", "/webauthn/registration/finish", nil)
	cred := &gw.Credential{ID: []byte("c1")}
	// Must not panic.
	recordWebAuthnRegistered(deps, r, cred)
	recordWebAuthnAttestationDenied(deps, r, &webauthn.AttestationDeniedError{Mode: webauthn.AttestationPolicyDenylist})
}
