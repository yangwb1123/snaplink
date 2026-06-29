package sso_test

// rootcov2_selfservice_test.go is the second-pass extension to the rootcov_*
// coverage suite. It targets the self-service / compliance handlers the first
// pass left at 0%: GDPR data export + account erasure (handle_data_export.go),
// the successful TOTP enrollment confirm leg (me_mfa.go recordTOTPEnrollSuccess),
// and the authenticated self-service WebAuthn registration ceremony
// (me_security.go).
//
// Every new helper carries the rcov2 prefix so it can never collide with the
// pre-existing rcov* helpers (rcovNewServer / rcovDirectLogin / rcovPostJSON /
// rcovDo are REUSED from rootcov_flow_test.go).

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/protocols/compliance"
)

// TestRcov2SS_DataExport covers GET /me/data-export — the GDPR Art. 15
// self-service export scoped to the authenticated bearer's own subject. A wired
// compliance.Exporter assembles the bundle from the same Memory* stores the
// server already uses.
func TestRcov2SS_DataExport(t *testing.T) {
	t.Parallel()
	users := defaultimpl.NewMemoryUserProvider()
	sessions := defaultimpl.NewMemorySessionManager()
	exporter := &compliance.Exporter{Users: users, Sessions: sessions}

	s := rcovNewServer(t,
		sso.WithUserProvider(users),
		sso.WithSessionManager(sessions),
		sso.WithSelfServiceDataExport(exporter),
	)
	access, _ := rcovDirectLogin(t, s)

	status, out := rcovDo(t, http.MethodGet, s.http.URL+"/me/data-export", access, nil)
	if status != http.StatusOK {
		t.Fatalf("data-export = %d body=%v, want 200", status, out)
	}
	// The bundle is scoped to the bearer's subject and carries a data map.
	if out["subject"] != rcovUser {
		t.Errorf("export subject = %v, want %q", out["subject"], rcovUser)
	}
	if _, ok := out["data"]; !ok {
		t.Errorf("export missing data map: %v", out)
	}

	// No bearer => 401 (meSubjectOrChallenge fires).
	status, _ = rcovDo(t, http.MethodGet, s.http.URL+"/me/data-export", "", nil)
	if status != http.StatusUnauthorized {
		t.Errorf("data-export no bearer = %d, want 401", status)
	}
}

// TestRcov2SS_AccountErase covers POST /me/account/erase — the GDPR Art. 17
// self-service erasure: the dry-run preview path, the confirmation guard
// (missing/wrong confirm => 400 on a real erase), and the irreversible commit.
func TestRcov2SS_AccountErase(t *testing.T) {
	t.Parallel()
	users := defaultimpl.NewMemoryUserProvider()
	sessions := defaultimpl.NewMemorySessionManager()
	clients := defaultimpl.NewMemoryClientStore()
	eraser := &compliance.Eraser{Users: users, Sessions: sessions, Clients: clients}

	s := rcovNewServer(t,
		sso.WithUserProvider(users),
		sso.WithSessionManager(sessions),
		sso.WithSelfServiceAccountErasure(eraser),
	)
	access, _ := rcovDirectLogin(t, s)

	// Dry-run preview: no confirm required, nothing mutated.
	status, out := rcovPostJSON(t, s.http.URL+"/me/account/erase", access, map[string]any{
		"dry_run": true,
	})
	if status != http.StatusOK {
		t.Fatalf("erase dry-run = %d body=%v, want 200", status, out)
	}
	if out["dry_run"] != true {
		t.Errorf("dry_run flag = %v, want true", out["dry_run"])
	}

	// Real erase WITHOUT a matching confirm => 400 (CSRF / accidental guard).
	status, _ = rcovPostJSON(t, s.http.URL+"/me/account/erase", access, map[string]any{
		"dry_run": false,
		"confirm": "not-my-subject",
	})
	if status != http.StatusBadRequest {
		t.Errorf("erase wrong confirm = %d, want 400", status)
	}

	// Real erase WITH the subject echoed => 200 commit.
	status, out = rcovPostJSON(t, s.http.URL+"/me/account/erase", access, map[string]any{
		"dry_run": false,
		"confirm": rcovUser,
	})
	if status != http.StatusOK {
		t.Fatalf("erase commit = %d body=%v, want 200", status, out)
	}
	if out["user_id"] != rcovUser {
		t.Errorf("erase report user_id = %v, want %q", out["user_id"], rcovUser)
	}
}

// rcov2CurrentTOTPCode derives the current 6-digit TOTP for a base32-no-pad
// secret (the encoding /me/mfa/totp/begin hands out). Standard HOTP over the
// 30s step — mirrors the authenticators package's own test helper so we never
// reach into unexported server internals.
func rcov2CurrentTOTPCode(t *testing.T, base32Secret string) string {
	t.Helper()
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(strings.ToUpper(strings.TrimSpace(base32Secret)))
	if err != nil {
		t.Fatalf("decode totp secret: %v", err)
	}
	step := time.Now().Unix() / 30
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	return fmt.Sprintf("%06d", bin%1_000_000)
}

// TestRcov2SS_TOTPEnrollSuccess covers the SUCCESS leg of POST
// /me/mfa/totp/confirm — a valid derived code persists the factor and fires
// recordTOTPEnrollSuccess (the first pass only exercised the wrong-code path).
func TestRcov2SS_TOTPEnrollSuccess(t *testing.T) {
	t.Parallel()
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	enroller := authenticators.NewTOTPEnroller(totpAuth)
	s := rcovNewServer(t,
		sso.WithMFAEnrollmentStore(defaultimpl.NewMemoryTOTPEnrollmentStore()),
		sso.WithTOTPEnroller(enroller),
	)
	access, _ := rcovDirectLogin(t, s)

	status, out := rcovPostJSON(t, s.http.URL+"/me/mfa/totp/begin", access, nil)
	if status != http.StatusOK {
		t.Fatalf("totp begin = %d body=%v", status, out)
	}
	secret, _ := out["secret"].(string)
	if secret == "" {
		t.Fatalf("no secret in begin response: %v", out)
	}

	status, out = rcovPostJSON(t, s.http.URL+"/me/mfa/totp/confirm", access, map[string]any{
		"secret": secret,
		"code":   rcov2CurrentTOTPCode(t, secret),
		"label":  "My phone",
	})
	if status != http.StatusCreated {
		t.Fatalf("totp confirm success = %d body=%v, want 201", status, out)
	}
	if out["factor_id"] == "" || out["factor_id"] == nil {
		t.Errorf("confirm returned no factor_id: %v", out)
	}

	// The enrolled factor surfaces in GET /me/mfa.
	status, _ = rcovDo(t, http.MethodGet, s.http.URL+"/me/mfa", access, nil)
	if status != http.StatusOK {
		t.Errorf("GET /me/mfa = %d, want 200", status)
	}
}

// rcov2WebAuthnRegistrar is a deterministic in-test registrar exercising the
// WebAuthnRegistrar seam: begin hands out fixed options + a session id, finish
// commits when the session matches. No external WebAuthn ceremony machinery is
// needed to drive the server-side handler bodies (begin/finish success + error).
type rcov2WebAuthnRegistrar struct {
	session string
	fail    bool
}

func (r *rcov2WebAuthnRegistrar) BeginRegistration(_ context.Context, userID, _ string) ([]byte, string, error) {
	r.session = "sess-" + userID
	return []byte(`{"publicKey":{"challenge":"AAAA"}}`), r.session, nil
}

func (r *rcov2WebAuthnRegistrar) FinishRegistration(_ context.Context, sessionID string, _ *http.Request) (string, error) {
	if r.fail || sessionID != r.session {
		return "", errors.New("attestation invalid")
	}
	return "cred-123", nil
}

// TestRcov2SS_WebAuthnRegister covers POST /me/mfa/webauthn/begin + /finish:
// the begin success path, the finish success path, and the missing-session-id
// 400 branch.
func TestRcov2SS_WebAuthnRegister(t *testing.T) {
	t.Parallel()
	reg := &rcov2WebAuthnRegistrar{}
	s := rcovNewServer(t, sso.WithWebAuthnRegistrar(reg))
	access, _ := rcovDirectLogin(t, s)

	status, out := rcovPostJSON(t, s.http.URL+"/me/mfa/webauthn/begin", access, map[string]any{
		"display_name": "Alice key",
	})
	if status != http.StatusOK {
		t.Fatalf("webauthn begin = %d body=%v, want 200", status, out)
	}
	sessionID, _ := out["session_id"].(string)
	if sessionID == "" {
		t.Fatalf("begin returned no session_id: %v", out)
	}

	// Finish with the session id from begin => 201 created.
	status, out = rcovDo(t, http.MethodPost,
		s.http.URL+"/me/mfa/webauthn/finish?session_id="+sessionID, access, map[string]any{})
	if status != http.StatusCreated {
		t.Fatalf("webauthn finish = %d body=%v, want 201", status, out)
	}
	if out["credential_id"] == "" || out["credential_id"] == nil {
		t.Errorf("finish returned no credential_id: %v", out)
	}

	// Missing session_id => 400.
	status, _ = rcovPostJSON(t, s.http.URL+"/me/mfa/webauthn/finish", access, map[string]any{})
	if status != http.StatusBadRequest {
		t.Errorf("webauthn finish no session = %d, want 400", status)
	}
}

// TestRcov2SS_WebAuthnRegisterFinishFailure covers the finish FAILURE branch
// (attestation rejected => 400 webauthn_registration).
func TestRcov2SS_WebAuthnRegisterFinishFailure(t *testing.T) {
	t.Parallel()
	reg := &rcov2WebAuthnRegistrar{fail: true}
	s := rcovNewServer(t, sso.WithWebAuthnRegistrar(reg))
	access, _ := rcovDirectLogin(t, s)

	status, out := rcovPostJSON(t, s.http.URL+"/me/mfa/webauthn/begin", access, nil)
	if status != http.StatusOK {
		t.Fatalf("webauthn begin = %d body=%v", status, out)
	}
	sessionID, _ := out["session_id"].(string)

	status, _ = rcovDo(t, http.MethodPost,
		s.http.URL+"/me/mfa/webauthn/finish?session_id="+sessionID, access, map[string]any{})
	if status != http.StatusBadRequest {
		t.Errorf("webauthn finish (rejected) = %d, want 400", status)
	}
}
