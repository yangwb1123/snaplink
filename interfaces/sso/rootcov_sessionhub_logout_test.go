package sso_test

// rootcov_sessionhub_logout_test.go covers POST /logout and GET /end_session
// actually reaching platform/lifecycle/sessionhub.Coordinator.Logout, closing
// the gap where a fully-built, unit-tested cross-protocol logout coordinator
// (SAML SLO fan-out included) had zero production callers: a login that had
// a SAML leg linked kept its SAML SP session alive indefinitely no matter
// which real logout path the user took.

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/lifecycle/sessionhub"
)

// recordingSAMLTrigger is a fake sessionhub.SAMLLogoutTrigger recording every
// Fanout call, standing in for infrastructure/saml's real IdP handlers (a
// separate Go module not available to this package's tests).
type recordingSAMLTrigger struct {
	calls int
	subs  []string
}

func (r *recordingSAMLTrigger) Fanout(_ context.Context, subject, _ string) {
	r.calls++
	r.subs = append(r.subs, subject)
}

// linkSAMLLegForSession simulates what infrastructure/saml's ACS handler does
// at a SAML-federated login: it finds the global_sid the CORE leg was
// already linked under for sessionID (the real login flow's linkGlobalSession
// already ran, since it fires unconditionally whenever a SessionManager is
// wired) and adds a SAML leg under that SAME global_sid.
func linkSAMLLegForSession(t *testing.T, hub *sessionhub.Coordinator, userID, sessionID string) {
	t.Helper()
	records, err := hub.ListBySubject(context.Background(), userID)
	if err != nil {
		t.Fatalf("ListBySubject: %v", err)
	}
	for _, r := range records {
		if r.Protocol == sessionhub.ProtocolCore && r.ExternalRef == sessionID {
			if err := hub.Link(context.Background(), r.GlobalSID, sessionhub.ProtocolSAML, "saml-session-index", userID); err != nil {
				t.Fatalf("link SAML leg: %v", err)
			}
			return
		}
	}
	t.Fatalf("no core leg found for session %q — linkGlobalSession did not run", sessionID)
}

// TestRcov_Logout_TriggersSAMLSLOForLinkedSession proves POST /logout fires
// the SAML SLO fan-out for a session that had a SAML leg linked, and that a
// session with NO SAML leg (the common case) does not spuriously trigger it.
func TestRcov_Logout_TriggersSAMLSLOForLinkedSession(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)
	saml := &recordingSAMLTrigger{}
	s.srv.SessionHub().SetSAMLTrigger(saml)

	access, _ := rcovDirectLogin(t, s)
	sessions, err := s.sessions.ListByUser(context.Background(), rcovUser)
	if err != nil || len(sessions) == 0 {
		t.Fatalf("expected a session created at login, got %v (err=%v)", sessions, err)
	}
	sessionID := sessions[0].ID
	linkSAMLLegForSession(t, s.srv.SessionHub(), rcovUser, sessionID)

	req, _ := http.NewRequest(http.MethodPost, s.http.URL+"/logout", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("logout request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout status = %d, want 200", resp.StatusCode)
	}

	if saml.calls != 1 {
		t.Fatalf("SAML SLO Fanout calls = %d, want 1", saml.calls)
	}
	if len(saml.subs) != 1 || saml.subs[0] != rcovUser {
		t.Fatalf("SAML SLO Fanout subject = %v, want [%s]", saml.subs, rcovUser)
	}
}

// TestRcov_Logout_NoSAMLLegNeverTriggersFanout proves an ordinary
// OIDC/session-only login (no SAML leg ever linked) never fires the SAML
// fan-out — Coordinator.Logout's "where applicable" gate is doing its job.
func TestRcov_Logout_NoSAMLLegNeverTriggersFanout(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)
	saml := &recordingSAMLTrigger{}
	s.srv.SessionHub().SetSAMLTrigger(saml)

	access, _ := rcovDirectLogin(t, s)
	req, _ := http.NewRequest(http.MethodPost, s.http.URL+"/logout", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("logout request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout status = %d, want 200", resp.StatusCode)
	}

	if saml.calls != 0 {
		t.Fatalf("SAML SLO Fanout calls = %d, want 0 (no SAML leg linked)", saml.calls)
	}
}

// TestRcov_EndSession_TriggersSAMLSLOForLinkedSession proves GET
// /end_session (OIDC RP-Initiated Logout) ALSO reaches the SAML SLO
// fan-out, via the same sessionhub wiring as POST /logout.
func TestRcov_EndSession_TriggersSAMLSLOForLinkedSession(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewEd25519JWTIssuer()
	s := rcovNewServer(t, sso.WithTokenIssuer("jwt", iss), sso.WithIDTokenIssuer(iss))
	saml := &recordingSAMLTrigger{}
	s.srv.SessionHub().SetSAMLTrigger(saml)

	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider": "password", "client_id": rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"scope":      []string{"openid"},
	})
	if status != http.StatusOK {
		t.Fatalf("login status=%d body=%v", status, out)
	}
	idToken, _ := out["id_token"].(string)
	if idToken == "" {
		t.Fatalf("login produced no id_token: %v", out)
	}
	sessions, err := s.sessions.ListByUser(context.Background(), rcovUser)
	if err != nil || len(sessions) == 0 {
		t.Fatalf("expected a session created at login, got %v (err=%v)", sessions, err)
	}
	linkSAMLLegForSession(t, s.srv.SessionHub(), rcovUser, sessions[0].ID)

	resp, err := http.Get(s.http.URL + "/end_session?id_token_hint=" + url.QueryEscape(idToken))
	if err != nil {
		t.Fatalf("end_session request: %v", err)
	}
	_ = resp.Body.Close()

	if saml.calls != 1 {
		t.Fatalf("SAML SLO Fanout calls = %d, want 1", saml.calls)
	}
}
