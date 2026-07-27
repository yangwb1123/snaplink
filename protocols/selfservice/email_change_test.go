package selfservice

import (
	"net/http"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

func TestHandleMyEmailChange_HappyPath(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	sender := &stubEmailChangeSender{}
	d.emailChangeSender = sender

	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"new_email":"new@example.com"}`)
	HandleMyEmailChange(d, ctx, "alice")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if decodeBody(t, rec)["status"] != "sent" {
		t.Fatal("expected status=sent")
	}
	if sender.calls != 1 || sender.lastEmail != "new@example.com" {
		t.Errorf("sender not invoked correctly: calls=%d email=%q", sender.calls, sender.lastEmail)
	}
	toks, _ := d.emailChange.ListByUser(t.Context(), "alice")
	if len(toks) != 1 || toks[0].NewEmail != "new@example.com" {
		t.Fatalf("expected 1 pending email-change token bound to new@example.com, got %v", toks)
	}
}

func TestHandleMyEmailChange_InvalidEmail(t *testing.T) {
	t.Parallel()
	cases := []string{`{"new_email":""}`, `{"new_email":"not-an-email"}`}
	for _, body := range cases {
		d := newTestDeps()
		d.emailChangeSender = &stubEmailChangeSender{}
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, body)
		HandleMyEmailChange(d, ctx, "alice")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400", body, rec.Code)
		}
	}
}

func seedEmailChangeToken(t *testing.T, d *testDeps, token, userID, newEmail string) {
	t.Helper()
	if err := d.emailChange.Issue(t.Context(), &core.EmailChangeToken{
		Token: token, UserID: userID, NewEmail: newEmail, ExpiresAt: futureExpiry(),
	}); err != nil {
		t.Fatalf("seed email change token: %v", err)
	}
}

func TestHandleMyEmailVerify_HappyPath(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	_ = d.users.CreateOrUpdate(t.Context(), &core.User{ID: "alice", Email: "old@example.com"})
	seedEmailChangeToken(t, d, "change-tok", "alice", "new@example.com")

	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"token":"change-tok"}`)
	HandleMyEmailVerify(d, ctx, "alice")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if got := decodeBody(t, rec)["email"]; got != "new@example.com" {
		t.Errorf("response email = %v, want new@example.com", got)
	}
	u, _ := d.users.GetByID(t.Context(), "alice")
	if u.Email != "new@example.com" {
		t.Errorf("stored email = %q, want new@example.com", u.Email)
	}
}

func TestHandleMyEmailVerify_WrongUserToken(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	_ = d.users.CreateOrUpdate(t.Context(), &core.User{ID: "alice"})
	seedEmailChangeToken(t, d, "change-tok", "alice", "new@example.com")

	// mallory tries to redeem alice's token for herself.
	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"token":"change-tok"}`)
	HandleMyEmailVerify(d, ctx, "mallory")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := decodeBody(t, rec)["error"]; got != core.ErrEmailChangeInvalid {
		t.Fatalf("error = %v, want %s", got, core.ErrEmailChangeInvalid)
	}
	u, _ := d.users.GetByID(t.Context(), "alice")
	if u.Email == "new@example.com" {
		t.Error("a token consumed by the wrong user must not commit the email change")
	}
}

func TestHandleMyEmailVerify_UnknownOrExpiredToken(t *testing.T) {
	t.Parallel()
	t.Run("unknown token", func(t *testing.T) {
		d := newTestDeps()
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"token":"nope"}`)
		HandleMyEmailVerify(d, ctx, "alice")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
	t.Run("expired token", func(t *testing.T) {
		d := newTestDeps()
		_ = d.emailChange.Issue(t.Context(), &core.EmailChangeToken{
			Token: "change-tok", UserID: "alice", NewEmail: "new@example.com", ExpiresAt: pastExpiry(),
		})
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"token":"change-tok"}`)
		HandleMyEmailVerify(d, ctx, "alice")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}
