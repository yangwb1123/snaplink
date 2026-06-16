package idp

import (
	"context"
	"net/http"
	"testing"
)

// TestSLO_SessionIndexNarrowsTermination proves the IdP SLO handler honors the
// LogoutRequest's SessionIndex: with the subject holding TWO live sessions, a
// signed LogoutRequest carrying ONE session's id as its SessionIndex terminates
// ONLY that session; the subject's other session survives. This locks the
// per-session scoping branch in terminateSubjectSessions (s.ID != sessionIndex).
func TestSLO_SessionIndexNarrowsTermination(t *testing.T) {
	const nameID = "multi-idp@example.com"
	hh, spKey, sid1 := newSLOHarness(t, nameID)

	// A SECOND live session for the SAME subject.
	sess2, err := hh.sessions.Create(context.Background(), nameID)
	if err != nil {
		t.Fatalf("create second session: %v", err)
	}

	// LogoutRequest narrowed to sid1.
	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spEntityID, nameID: nameID, sessionIndex: sid1}, "", spKey)
	rec := hh.getSLO(q)
	if rec.Code != http.StatusFound {
		t.Fatalf("SLO status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}

	// sid1 (matching SessionIndex) gone; sess2 (non-matching) survives — no
	// cross-session blanket wipe.
	if s, err := hh.sessions.Get(context.Background(), sid1); err == nil && s != nil {
		t.Fatalf("session %q (matching SessionIndex) should be terminated", sid1)
	}
	if _, err := hh.sessions.Get(context.Background(), sess2.ID); err != nil {
		t.Fatalf("session %q (non-matching SessionIndex) wrongly terminated: %v", sess2.ID, err)
	}
}

// TestSLO_UnknownSubject_StillSuccess proves the no-session-existence oracle: a
// signed LogoutRequest for a subject with NO local sessions still yields a
// Success LogoutResponse (302) — terminateSubjectSessions destroys zero sessions
// but never errors or leaks that nothing matched.
func TestSLO_UnknownSubject_StillSuccess(t *testing.T) {
	// Harness seeds a session for "present@example.com" but we log out a DIFFERENT
	// subject that has none.
	hh, spKey, _ := newSLOHarness(t, "present@example.com")

	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spEntityID, nameID: "absent@example.com"}, "", spKey)
	rec := hh.getSLO(q)
	if rec.Code != http.StatusFound {
		t.Fatalf("SLO for a session-less subject status = %d, want 302 (no existence oracle); body=%s", rec.Code, rec.Body.String())
	}
}
