package selfservice

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/snaplink/sso/shared/core"
)

// alwaysResolve/alwaysDeliver build PasswordResetResolver/DeliveryResolver
// funcs that succeed for a known userID and fail (unknown identifier) for
// anything else — the shape production wires from a real UserProvider-backed
// resolver, simplified here to a table since the resolver itself isn't a
// storage interface (it's provided by the operator, e.g. by username lookup).
func alwaysResolve(known map[string]string) func(context.Context, string) (string, error) {
	return func(_ context.Context, identifier string) (string, error) {
		if uid, ok := known[identifier]; ok {
			return uid, nil
		}
		return "", errors.New("not found")
	}
}

func alwaysDeliver(target string) func(context.Context, string) (string, error) {
	return func(context.Context, string) (string, error) { return target, nil }
}

func TestHandleForgotPassword_HappyPath(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	_ = d.users.CreateOrUpdate(t.Context(), &core.User{ID: "alice"})
	d.resetResolver = alwaysResolve(map[string]string{"alice@example.com": "alice"})
	d.resetDeliveryResolver = alwaysDeliver("alice@example.com")
	sender := &stubResetSender{}
	d.resetSender = sender

	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"identifier":"alice@example.com"}`)
	HandleForgotPassword(d, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if decodeBody(t, rec)["status"] != "sent" {
		t.Fatal("expected status=sent")
	}
	if sender.calls != 1 || sender.lastTarget != "alice@example.com" {
		t.Errorf("sender not invoked correctly: calls=%d target=%q", sender.calls, sender.lastTarget)
	}
	toks, _ := d.passwordReset.ListByUser(t.Context(), "alice")
	if len(toks) != 1 {
		t.Fatalf("expected 1 pending reset token, got %d", len(toks))
	}
}

// TestHandleForgotPassword_AntiEnumeration proves the §4 anti-enumeration
// invariant: an unknown identifier, a missing resolver, and a delivery
// failure are ALL indistinguishable from success on the wire (always 200
// {status:"sent"}), even though no token is actually issued/delivered.
func TestHandleForgotPassword_AntiEnumeration(t *testing.T) {
	t.Parallel()
	cases := map[string]func(d *testDeps){
		"unknown identifier": func(d *testDeps) {
			d.resetResolver = alwaysResolve(map[string]string{"known@example.com": "alice"})
			d.resetDeliveryResolver = alwaysDeliver("x")
			d.resetSender = &stubResetSender{}
		},
		"no resolver wired": func(d *testDeps) {},
		"delivery failure": func(d *testDeps) {
			d.resetResolver = alwaysResolve(map[string]string{"alice@example.com": "alice"})
			d.resetDeliveryResolver = alwaysDeliver("alice@example.com")
			d.resetSender = &stubResetSender{err: errors.New("smtp down")}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			d := newTestDeps()
			setup(d)
			ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"identifier":"alice@example.com"}`)
			HandleForgotPassword(d, ctx)
			if rec.Code != http.StatusOK || decodeBody(t, rec)["status"] != "sent" {
				t.Fatalf("case %q: must 200 {status:sent} regardless, got %d body=%s", name, rec.Code, rec.Body.String())
			}
		})
	}
}

func seedResetToken(t *testing.T, d *testDeps, token, userID string) {
	t.Helper()
	_ = d.users.CreateOrUpdate(t.Context(), &core.User{ID: userID})
	if err := d.passwordReset.Issue(t.Context(), &core.PasswordResetToken{
		Token: token, UserID: userID, ExpiresAt: futureExpiry(),
	}); err != nil {
		t.Fatalf("seed reset token: %v", err)
	}
}

func TestHandleResetPassword_HappyPath(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	seedResetToken(t, d, "reset-tok", "alice")
	sess, err := d.sessions.Create(t.Context(), "alice")
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}

	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"token":"reset-tok","new_password":"newpass123"}`)
	HandleResetPassword(d, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if err := d.passwords.VerifyPassword(t.Context(), "alice", "newpass123"); err != nil {
		t.Errorf("new password not set: %v", err)
	}
	if _, err := d.sessions.Get(t.Context(), sess.ID); err == nil {
		t.Error("existing sessions must be revoked after a password reset")
	}
}

func TestHandleResetPassword_UnknownOrExpiredToken(t *testing.T) {
	t.Parallel()
	t.Run("unknown token", func(t *testing.T) {
		d := newTestDeps()
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"token":"nope","new_password":"newpass123"}`)
		HandleResetPassword(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if got := decodeBody(t, rec)["error"]; got != core.ErrResetInvalid {
			t.Fatalf("error = %v, want %s", got, core.ErrResetInvalid)
		}
	})
	t.Run("expired token", func(t *testing.T) {
		d := newTestDeps()
		_ = d.users.CreateOrUpdate(t.Context(), &core.User{ID: "alice"})
		_ = d.passwordReset.Issue(t.Context(), &core.PasswordResetToken{Token: "reset-tok", UserID: "alice", ExpiresAt: pastExpiry()})
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"token":"reset-tok","new_password":"newpass123"}`)
		HandleResetPassword(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestHandleResetPassword_DoubleConsumption(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	seedResetToken(t, d, "reset-tok", "alice")
	ctx1, rec1 := newCtx(http.MethodPost, core.ContentTypeJSON, `{"token":"reset-tok","new_password":"newpass123"}`)
	HandleResetPassword(d, ctx1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first use: status = %d, want 200", rec1.Code)
	}
	ctx2, rec2 := newCtx(http.MethodPost, core.ContentTypeJSON, `{"token":"reset-tok","new_password":"another123"}`)
	HandleResetPassword(d, ctx2)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("replay: status = %d, want 400", rec2.Code)
	}
}

// TestHandleResetPassword_PolicyViolationConsumesToken documents a real
// behavior worth locking in: checkPasswordPolicy runs AFTER Consume, so a
// policy-rejected reset still burns the single-use token — the caller must
// request a new one, they can't retry with a compliant password.
func TestHandleResetPassword_PolicyViolationConsumesToken(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	seedResetToken(t, d, "reset-tok", "alice")
	d.passwordPolicy = policyRequiringLength(12)

	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"token":"reset-tok","new_password":"short"}`)
	HandleResetPassword(d, ctx)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := decodeBody(t, rec)["error"]; got != core.ErrPasswordPolicyViolation {
		t.Fatalf("error = %v, want %s", got, core.ErrPasswordPolicyViolation)
	}
	// Token already consumed: a retry with a compliant password must fail too.
	ctx2, rec2 := newCtx(http.MethodPost, core.ContentTypeJSON, `{"token":"reset-tok","new_password":"longenoughpass"}`)
	HandleResetPassword(d, ctx2)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("retry after policy failure: status = %d, want 400 (token burned)", rec2.Code)
	}
}
