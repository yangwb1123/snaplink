package selfserviceaccount

import (
	"net/http"
	"testing"

	"github.com/snaplink/sso/shared/core"
)

func TestHandleChangeMyPassword_HappyPath(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	_ = d.passwords.SetPassword(t.Context(), "user-1", "old-password")

	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"current_password":"old-password","new_password":"new-password-123"}`)
	HandleChangeMyPassword(d, ctx)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204, body=%s", rec.Code, rec.Body.String())
	}
	if err := d.passwords.VerifyPassword(t.Context(), "user-1", "new-password-123"); err != nil {
		t.Errorf("new password not set: %v", err)
	}
}

func TestHandleChangeMyPassword_WrongCurrentPassword(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	_ = d.passwords.SetPassword(t.Context(), "user-1", "old-password")

	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"current_password":"wrong","new_password":"new-password-123"}`)
	HandleChangeMyPassword(d, ctx)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := decodeBody(t, rec)["error"]; got != core.ErrInvalidPassword {
		t.Fatalf("error = %v, want %s", got, core.ErrInvalidPassword)
	}
	if err := d.passwords.VerifyPassword(t.Context(), "user-1", "old-password"); err != nil {
		t.Error("password must be unchanged after a rejected attempt")
	}
}

func TestHandleChangeMyPassword_MissingFields(t *testing.T) {
	t.Parallel()
	cases := []string{
		`{"new_password":"new-password-123"}`,
		`{"current_password":"old-password"}`,
	}
	for _, body := range cases {
		d := newTestDeps()
		_ = d.passwords.SetPassword(t.Context(), "user-1", "old-password")
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, body)
		HandleChangeMyPassword(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400", body, rec.Code)
		}
	}
}

func TestHandleChangeMyPassword_PolicyViolation(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	_ = d.passwords.SetPassword(t.Context(), "user-1", "old-password")
	d.passwordPolicy = policyRequiringLength(20)

	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"current_password":"old-password","new_password":"short"}`)
	HandleChangeMyPassword(d, ctx)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := decodeBody(t, rec)["error"]; got != core.ErrPasswordPolicyViolation {
		t.Fatalf("error = %v, want %s", got, core.ErrPasswordPolicyViolation)
	}
}

func TestHandleChangeMyPassword_ResidencyGateDenies(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	_ = d.passwords.SetPassword(t.Context(), "user-1", "old-password")
	d.residencyWriteDeny = "region_not_allowed"

	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"current_password":"old-password","new_password":"new-password-123"}`)
	HandleChangeMyPassword(d, ctx)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestHandleWebAuthnRegisterBegin(t *testing.T) {
	t.Parallel()
	t.Run("no registrar 501", func(t *testing.T) {
		d := newTestDeps() // webauthn left nil
		ctx, rec := newCtx(http.MethodPost, "", "")
		HandleWebAuthnRegisterBegin(d, ctx)
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("status = %d, want 501", rec.Code)
		}
	})

	t.Run("happy path returns session + options", func(t *testing.T) {
		d := newTestDeps()
		d.webauthn = stubWebAuthnRegistrar{}
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"display_name":"My Key"}`)
		HandleWebAuthnRegisterBegin(d, ctx)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		resp := decodeBody(t, rec)
		if resp["session_id"] != "session-for-user-1" {
			t.Errorf("session_id = %v, want session-for-user-1", resp["session_id"])
		}
	})
}

func TestHandleWebAuthnRegisterFinish(t *testing.T) {
	t.Parallel()
	t.Run("no registrar 501", func(t *testing.T) {
		d := newTestDeps() // webauthn left nil
		ctx, rec := newCtx(http.MethodPost, "", "")
		HandleWebAuthnRegisterFinish(d, ctx)
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("status = %d, want 501", rec.Code)
		}
	})

	t.Run("missing session_id 400", func(t *testing.T) {
		d := newTestDeps()
		d.webauthn = stubWebAuthnRegistrar{}
		ctx, rec := newCtx(http.MethodPost, "", "")
		HandleWebAuthnRegisterFinish(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("happy path returns credential_id", func(t *testing.T) {
		d := newTestDeps()
		d.webauthn = stubWebAuthnRegistrar{credID: "cred-123"}
		req, rec := newCtx(http.MethodPost, "", "")
		req.Request().URL.RawQuery = "session_id=sess-1"
		HandleWebAuthnRegisterFinish(d, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
		}
		if got := decodeBody(t, rec)["credential_id"]; got != "cred-123" {
			t.Errorf("credential_id = %v, want cred-123", got)
		}
	})
}
