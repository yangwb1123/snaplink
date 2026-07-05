package selfservice

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

func TestHandleSelfRegister_ModeA_HappyPath(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"username":"alice","password":"s3cret!!","email":"alice@example.com"}`)
	HandleSelfRegister(d, ctx)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeBody(t, rec)
	if resp["status"] != "created" || resp["user_id"] != "alice" {
		t.Fatalf("unexpected body: %v", resp)
	}
	u, err := d.users.GetByID(t.Context(), "alice")
	if err != nil || u == nil {
		t.Fatalf("user not created: %v", err)
	}
	if u.Attributes["email_verified"] != "true" {
		t.Errorf("email_verified = %q, want true (email was provided)", u.Attributes["email_verified"])
	}
	if err := d.passwords.VerifyPassword(t.Context(), "alice", "s3cret!!"); err != nil {
		t.Errorf("password not set: %v", err)
	}
	if rec.Header().Get("Pragma") != "no-cache" {
		t.Error("missing no-store headers")
	}
}

func TestHandleSelfRegister_DuplicateUsername(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	_ = d.users.CreateOrUpdate(t.Context(), &core.User{ID: "alice"})
	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"username":"alice","password":"s3cret!!"}`)
	HandleSelfRegister(d, ctx)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	if got := decodeBody(t, rec)["error"]; got != core.ErrAccountExists {
		t.Fatalf("error = %v, want %s", got, core.ErrAccountExists)
	}
}

func TestHandleSelfRegister_MissingFields(t *testing.T) {
	t.Parallel()
	cases := []string{
		`{"password":"s3cret!!"}`,
		`{"username":"alice"}`,
		`{"username":"  ","password":"s3cret!!"}`,
	}
	for _, body := range cases {
		d := newTestDeps()
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, body)
		HandleSelfRegister(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400", body, rec.Code)
		}
	}
}

func TestHandleSelfRegister_RegistrationGateRejects(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	d.registrationGates = []spi.RegistrationGate{stubGate{err: errors.New("denied")}}
	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"username":"alice","password":"s3cret!!"}`)
	HandleSelfRegister(d, ctx)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if got := decodeBody(t, rec)["error"]; got != core.ErrRegistrationDenied {
		t.Fatalf("error = %v, want %s", got, core.ErrRegistrationDenied)
	}
	if _, err := d.users.GetByID(t.Context(), "alice"); err == nil {
		t.Error("gate-rejected signup must not create the user")
	}
}

func TestHandleSelfRegister_RateLimited(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	d.rateLimiter = stubRateLimiter{allow: false, retryAfter: 3500 * time.Millisecond}
	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"username":"alice","password":"s3cret!!"}`)
	HandleSelfRegister(d, ctx)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	// Ceiling division: 3.5s rounds up to 4.
	if got := rec.Header().Get("Retry-After"); got != "4" {
		t.Errorf("Retry-After = %q, want 4", got)
	}
}

func TestHandleSelfRegister_PasswordPolicyViolation(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	d.passwordPolicy = spi.NewPasswordPolicyValidator(spi.PasswordPolicyConfig{MinLength: 12})
	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"username":"alice","password":"short"}`)
	HandleSelfRegister(d, ctx)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := decodeBody(t, rec)["error"]; got != core.ErrPasswordPolicyViolation {
		t.Fatalf("error = %v, want %s", got, core.ErrPasswordPolicyViolation)
	}
	if _, err := d.users.GetByID(t.Context(), "alice"); err == nil {
		t.Error("policy-rejected signup must not create the user")
	}
}

func TestHandleSelfRegister_RollbackOnSetPasswordFailure(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	real := d.passwords
	d.passwordCredentialStoreOverride = &failingPasswordStore{real: real, failFor: "alice"}
	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"username":"alice","password":"s3cret!!"}`)
	HandleSelfRegister(d, ctx)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if _, err := d.users.GetByID(t.Context(), "alice"); err == nil {
		t.Error("user must be rolled back after SetPassword failure")
	}
}

func TestHandleSelfRegister_ModeB_MandatoryVerification(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	d.requireVerification = true
	sender := &stubEmailVerificationSender{}
	d.emailVerifySender = sender

	t.Run("missing email 400", func(t *testing.T) {
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"username":"bob","password":"s3cret!!"}`)
		HandleSelfRegister(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("pending, user not created, token issued+sent", func(t *testing.T) {
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"username":"bob","password":"s3cret!!","email":"bob@example.com"}`)
		HandleSelfRegister(d, ctx)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
		}
		if got := decodeBody(t, rec)["status"]; got != "pending" {
			t.Fatalf("status field = %v, want pending", got)
		}
		if _, err := d.users.GetByID(t.Context(), "bob"); err == nil {
			t.Error("Mode B must NOT create the user before verification")
		}
		if sender.calls != 1 || sender.lastEmail != "bob@example.com" {
			t.Errorf("verification sender not called correctly: calls=%d email=%q", sender.calls, sender.lastEmail)
		}
	})
}
