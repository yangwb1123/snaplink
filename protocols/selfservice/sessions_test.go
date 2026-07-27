package selfservice

import (
	"net/http"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

func TestHandleMySessions_ListsOwnSessionsOnly(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	_, _ = d.sessions.Create(t.Context(), "user-1")
	_, _ = d.sessions.Create(t.Context(), "user-1")
	_, _ = d.sessions.Create(t.Context(), "someone-else")

	ctx, rec := newCtx(http.MethodGet, "", "")
	HandleMySessions(d, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	resp := decodeBody(t, rec)
	sessions, _ := resp["sessions"].([]any)
	if len(sessions) != 2 {
		t.Fatalf("got %d sessions, want 2 (own only)", len(sessions))
	}
}

func TestHandleDeleteMySession(t *testing.T) {
	t.Parallel()
	t.Run("happy path", func(t *testing.T) {
		d := newTestDeps()
		sess, _ := d.sessions.Create(t.Context(), "user-1")
		rec := servePath(http.MethodDelete, "/sessions/me/:id", "/sessions/me/"+sess.ID, "",
			func(ctx core.HandlerContext) { HandleDeleteMySession(d, ctx) })
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", rec.Code)
		}
		if _, err := d.sessions.Get(t.Context(), sess.ID); err == nil {
			t.Error("session should be destroyed")
		}
	})

	t.Run("unknown session 404", func(t *testing.T) {
		d := newTestDeps()
		rec := servePath(http.MethodDelete, "/sessions/me/:id", "/sessions/me/ghost", "",
			func(ctx core.HandlerContext) { HandleDeleteMySession(d, ctx) })
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})

	t.Run("other user's session 404 (oracle-safe)", func(t *testing.T) {
		d := newTestDeps()
		sess, _ := d.sessions.Create(t.Context(), "someone-else")
		rec := servePath(http.MethodDelete, "/sessions/me/:id", "/sessions/me/"+sess.ID, "",
			func(ctx core.HandlerContext) { HandleDeleteMySession(d, ctx) })
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
		if _, err := d.sessions.Get(t.Context(), sess.ID); err != nil {
			t.Error("a cross-user delete attempt must not destroy the other user's session")
		}
	})
}

func TestHandleRevokeMySessions_KeepsCurrentByDefault(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	current, _ := d.sessions.Create(t.Context(), "user-1")
	other, _ := d.sessions.Create(t.Context(), "user-1")
	d.authClaims = &core.TokenClaims{Subject: "user-1", SID: current.ID}

	ctx, rec := newCtx(http.MethodDelete, "", "")
	HandleRevokeMySessions(d, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if _, err := d.sessions.Get(t.Context(), current.ID); err != nil {
		t.Error("the current session (by SID) must be preserved by default")
	}
	if _, err := d.sessions.Get(t.Context(), other.ID); err == nil {
		t.Error("other sessions must be revoked")
	}
}

func TestHandleRevokeMySessions_AllTrueRevokesCurrentToo(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	current, _ := d.sessions.Create(t.Context(), "user-1")
	d.authClaims = &core.TokenClaims{Subject: "user-1", SID: current.ID}

	req, rec := newCtx(http.MethodDelete, "", "")
	req.Request().URL.RawQuery = "all=true"
	HandleRevokeMySessions(d, req)
	_ = rec

	if _, err := d.sessions.Get(t.Context(), current.ID); err == nil {
		t.Error("?all=true must revoke the current session too")
	}
}

func TestHandleRevokeAllMySessions_AlwaysRevokesEverything(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	current, _ := d.sessions.Create(t.Context(), "user-1")
	d.authClaims = &core.TokenClaims{Subject: "user-1", SID: current.ID}

	ctx, rec := newCtx(http.MethodPost, "", "")
	HandleRevokeAllMySessions(d, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if _, err := d.sessions.Get(t.Context(), current.ID); err == nil {
		t.Error("revoke-all-my-sessions must revoke the current session too, unlike RevokeMySessions")
	}
}
