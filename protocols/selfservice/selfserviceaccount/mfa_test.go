package selfserviceaccount

import (
	"net/http"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

func TestHandleMyMFAFactors_ListsOwnFactors(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	writer := d.mfaStore.(core.TOTPEnrollmentWriter)
	if err := writer.AddTOTPFactor(t.Context(), "user-1", "f1", "Authenticator", []byte("secret")); err != nil {
		t.Fatalf("seed factor: %v", err)
	}

	ctx, rec := newCtx(http.MethodGet, "", "")
	HandleMyMFAFactors(d, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	resp := decodeBody(t, rec)
	factors, _ := resp["factors"].([]any)
	if len(factors) != 1 {
		t.Fatalf("got %d factors, want 1", len(factors))
	}
}

func TestHandleDeleteMyMFAFactor(t *testing.T) {
	t.Parallel()
	t.Run("happy path", func(t *testing.T) {
		d := newTestDeps()
		writer := d.mfaStore.(core.TOTPEnrollmentWriter)
		_ = writer.AddTOTPFactor(t.Context(), "user-1", "f1", "Authenticator", []byte("secret"))
		rec := servePath(http.MethodDelete, "/me/mfa/:id", "/me/mfa/f1", "",
			func(ctx core.HandlerContext) { HandleDeleteMyMFAFactor(d, ctx) })
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", rec.Code)
		}
		factors, _ := d.mfaStore.ListFactors(t.Context(), "user-1")
		if len(factors) != 0 {
			t.Error("factor should be removed")
		}
	})

	t.Run("unknown factor 404", func(t *testing.T) {
		d := newTestDeps()
		rec := servePath(http.MethodDelete, "/me/mfa/:id", "/me/mfa/ghost", "",
			func(ctx core.HandlerContext) { HandleDeleteMyMFAFactor(d, ctx) })
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})

	t.Run("other user's factor 404 (oracle-safe)", func(t *testing.T) {
		d := newTestDeps()
		writer := d.mfaStore.(core.TOTPEnrollmentWriter)
		_ = writer.AddTOTPFactor(t.Context(), "someone-else", "f1", "Authenticator", []byte("secret"))
		rec := servePath(http.MethodDelete, "/me/mfa/:id", "/me/mfa/f1", "",
			func(ctx core.HandlerContext) { HandleDeleteMyMFAFactor(d, ctx) })
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
		factors, _ := d.mfaStore.ListFactors(t.Context(), "someone-else")
		if len(factors) != 1 {
			t.Error("cross-user delete attempt must not remove the other user's factor")
		}
	})
}

func TestHandleTOTPEnrollBegin(t *testing.T) {
	t.Parallel()
	t.Run("no enroller configured 501", func(t *testing.T) {
		d := newTestDeps() // totp left nil
		ctx, rec := newCtx(http.MethodPost, "", "")
		HandleTOTPEnrollBegin(d, ctx)
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("status = %d, want 501", rec.Code)
		}
	})

	t.Run("happy path returns secret + otpauth uri", func(t *testing.T) {
		d := newTestDeps()
		d.totp = stubTOTPEnroller{validCode: "123456"}
		ctx, rec := newCtx(http.MethodPost, "", "")
		HandleTOTPEnrollBegin(d, ctx)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		resp := decodeBody(t, rec)
		if resp["secret"] == "" || resp["secret"] == nil {
			t.Error("secret missing")
		}
		if resp["otpauth_uri"] == "" || resp["otpauth_uri"] == nil {
			t.Error("otpauth_uri missing")
		}
	})
}

func TestHandleTOTPEnrollConfirm(t *testing.T) {
	t.Parallel()
	t.Run("store lacks TOTPEnrollmentWriter 501", func(t *testing.T) {
		d := newTestDeps()
		d.mfaStore = localMFAStorePlain{} // no AddTOTPFactor
		d.totp = stubTOTPEnroller{validCode: "123456"}
		enroller := d.totp.(stubTOTPEnroller)
		secret, _ := enroller.GenerateSecret()
		body := `{"secret":"` + enroller.EncodeSecret(secret) + `","code":"123456"}`
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, body)
		HandleTOTPEnrollConfirm(d, ctx)
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("status = %d, want 501", rec.Code)
		}
	})

	t.Run("wrong code 400 oracle-safe", func(t *testing.T) {
		d := newTestDeps()
		enroller := stubTOTPEnroller{validCode: "123456"}
		d.totp = enroller
		secret, _ := enroller.GenerateSecret()
		body := `{"secret":"` + enroller.EncodeSecret(secret) + `","code":"000000"}`
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, body)
		HandleTOTPEnrollConfirm(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if got := decodeBody(t, rec)["error"]; got != core.ErrTOTPInvalidCode {
			t.Fatalf("error = %v, want %s", got, core.ErrTOTPInvalidCode)
		}
	})

	t.Run("missing secret/code 400", func(t *testing.T) {
		d := newTestDeps()
		d.totp = stubTOTPEnroller{validCode: "123456"}
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{}`)
		HandleTOTPEnrollConfirm(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("happy path persists factor", func(t *testing.T) {
		d := newTestDeps()
		enroller := stubTOTPEnroller{validCode: "123456"}
		d.totp = enroller
		secret, _ := enroller.GenerateSecret()
		body := `{"secret":"` + enroller.EncodeSecret(secret) + `","code":"123456","label":"My Phone"}`
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, body)
		HandleTOTPEnrollConfirm(d, ctx)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
		}
		resp := decodeBody(t, rec)
		if resp["label"] != "My Phone" {
			t.Errorf("label = %v, want My Phone", resp["label"])
		}
		factors, _ := d.mfaStore.ListFactors(t.Context(), "user-1")
		if len(factors) != 1 {
			t.Fatalf("factor not persisted: %v", factors)
		}
	})
}
