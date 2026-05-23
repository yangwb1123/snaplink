package sso_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/authenticators"
)

type stubSMS struct {
	err  error
	last string // last target the sender saw
}

func (s *stubSMS) Send(_ context.Context, target, _ string) error {
	s.last = target
	return s.err
}

// buildSendCodeServer wires a fresh Server with the phone authenticator (a
// spi.CodeSender) + the password authenticator (NOT a spi.CodeSender) so tests can
// hit both branches of handleSendCode's spi.CodeSender type assertion.
func buildSendCodeServer(t *testing.T, sms *stubSMS) (*httptest.Server, *audit.MemorySink) {
	t.Helper()

	store := authenticators.NewMemoryCodeStore()
	phone := authenticators.NewPhoneAuthenticator(store, sms)
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) { return nil, errors.New("nope") },
	))

	sink := audit.NewMemorySink(100)
	rec := audit.New(sink)

	srv := sso.NewServer(
		sso.WithAuthenticator(phone),
		sso.WithAuthenticator(pw),
		sso.WithAuditRecorder(rec),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, sink
}

func postSendCode(t *testing.T, srv *httptest.Server, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+"/auth/send-code", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST /auth/send-code: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(respBody, &out)
	return resp.StatusCode, out
}

func TestSendCode_HappyPath(t *testing.T) {
	sms := &stubSMS{}
	srv, sink := buildSendCodeServer(t, sms)

	code, body := postSendCode(t, srv, map[string]any{
		"provider": "phone",
		"target":   "+15551234567",
	})
	if code != http.StatusOK {
		t.Fatalf("status = %d, body = %v", code, body)
	}
	if body["status"] != "sent" {
		t.Errorf("status field = %v, want sent", body["status"])
	}
	if sms.last != "+15551234567" {
		t.Errorf("SMS sender saw target = %q", sms.last)
	}

	// One code_sent / success event should land in the audit ring.
	events, _ := sink.Query(context.Background(), audit.Query{
		Type: audit.EventCodeSent, Outcome: audit.OutcomeSuccess,
	})
	if len(events) != 1 {
		t.Errorf("audit events = %d, want 1", len(events))
	}
	// And the masked target lands in metadata — but NOT the raw value.
	if got, _ := events[0].Metadata["target"]; got == "+15551234567" {
		t.Errorf("target metadata should be masked, got raw value %q", got)
	}
}

func TestSendCode_MissingProvider(t *testing.T) {
	srv, _ := buildSendCodeServer(t, &stubSMS{})
	code, body := postSendCode(t, srv, map[string]any{"target": "+1"})
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	if body["error"] != "provider_and_target_required" {
		t.Errorf("error = %v", body["error"])
	}
}

func TestSendCode_MissingTarget(t *testing.T) {
	srv, _ := buildSendCodeServer(t, &stubSMS{})
	code, body := postSendCode(t, srv, map[string]any{"provider": "phone"})
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	if body["error"] != "provider_and_target_required" {
		t.Errorf("error = %v", body["error"])
	}
}

func TestSendCode_UnknownProvider(t *testing.T) {
	srv, _ := buildSendCodeServer(t, &stubSMS{})
	code, body := postSendCode(t, srv, map[string]any{
		"provider": "no-such-provider",
		"target":   "+1",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	if body["error"] != "unsupported_provider" {
		t.Errorf("error = %v", body["error"])
	}
}

func TestSendCode_ProviderIsNotCodeSender(t *testing.T) {
	// PasswordAuthenticator does NOT implement spi.CodeSender — the handler
	// must reject the request with the dedicated error code.
	srv, _ := buildSendCodeServer(t, &stubSMS{})
	code, body := postSendCode(t, srv, map[string]any{
		"provider": "password",
		"target":   "alice",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	if body["error"] != "provider_does_not_send_codes" {
		t.Errorf("error = %v", body["error"])
	}
}

func TestSendCode_SenderFailureRecordsFailureAuditEvent(t *testing.T) {
	sms := &stubSMS{err: errors.New("sms downstream is down")}
	srv, sink := buildSendCodeServer(t, sms)

	code, body := postSendCode(t, srv, map[string]any{
		"provider": "phone",
		"target":   "+15551234567",
	})
	if code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", code)
	}
	if body["error"] != "send_failed" {
		t.Errorf("error = %v", body["error"])
	}

	events, _ := sink.Query(context.Background(), audit.Query{
		Type: audit.EventCodeSent, Outcome: audit.OutcomeFailure,
	})
	if len(events) != 1 {
		t.Errorf("failure audit events = %d, want 1", len(events))
	}
}

func TestSendCode_BadJSON(t *testing.T) {
	srv, _ := buildSendCodeServer(t, &stubSMS{})
	resp, err := http.Post(srv.URL+"/auth/send-code", "application/json", bytes.NewReader([]byte("{not json")))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}
