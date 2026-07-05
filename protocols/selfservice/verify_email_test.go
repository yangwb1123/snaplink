package selfservice

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/snaplink/sso/shared/core"
	"golang.org/x/crypto/bcrypt"
)

// issueRawVerificationToken hashes rawToken the same way HandleVerifyEmail
// does (SHA-256 hex) and stores tok under that hash, so the test can drive
// HandleVerifyEmail with the raw token exactly as a real client would.
func issueRawVerificationToken(t *testing.T, d *testDeps, rawToken string, tok *core.EmailVerificationToken) {
	t.Helper()
	h := sha256.Sum256([]byte(rawToken))
	tok.Token = hex.EncodeToString(h[:])
	if err := d.emailVerify.Issue(t.Context(), tok); err != nil {
		t.Fatalf("issue verification token: %v", err)
	}
}

func TestHandleVerifyEmail_ModeB_HappyPath(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	pwHash, _ := bcrypt.GenerateFromPassword([]byte("s3cret!!"), bcrypt.DefaultCost)
	issueRawVerificationToken(t, d, "raw-token", &core.EmailVerificationToken{
		Username: "bob", Email: "bob@example.com", PasswordHash: string(pwHash),
		ExpiresAt: time.Now().Add(time.Hour),
	})

	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"token":"raw-token"}`)
	HandleVerifyEmail(d, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	u, err := d.users.GetByID(t.Context(), "bob")
	if err != nil || u == nil {
		t.Fatalf("user not created: %v", err)
	}
	if u.Attributes["email_verified"] != "true" {
		t.Error("email_verified must be true")
	}
	if err := d.passwords.VerifyPassword(t.Context(), "bob", "s3cret!!"); err != nil {
		t.Errorf("password hash not installed: %v", err)
	}
}

func TestHandleVerifyEmail_UnknownToken(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"token":"never-issued"}`)
	HandleVerifyEmail(d, ctx)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := decodeBody(t, rec)["error"]; got != core.ErrVerificationInvalid {
		t.Fatalf("error = %v, want %s", got, core.ErrVerificationInvalid)
	}
}

func TestHandleVerifyEmail_ExpiredToken(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	issueRawVerificationToken(t, d, "raw-token", &core.EmailVerificationToken{
		Username: "bob", Email: "bob@example.com", ExpiresAt: time.Now().Add(-time.Minute),
	})
	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"token":"raw-token"}`)
	HandleVerifyEmail(d, ctx)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if _, err := d.users.GetByID(t.Context(), "bob"); err == nil {
		t.Error("an expired token must not create the user")
	}
}

func TestHandleVerifyEmail_DoubleConsumption(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	issueRawVerificationToken(t, d, "raw-token", &core.EmailVerificationToken{
		Username: "bob", Email: "bob@example.com", ExpiresAt: time.Now().Add(time.Hour),
	})
	ctx1, rec1 := newCtx(http.MethodPost, core.ContentTypeJSON, `{"token":"raw-token"}`)
	HandleVerifyEmail(d, ctx1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first consume: status = %d, want 200", rec1.Code)
	}
	ctx2, rec2 := newCtx(http.MethodPost, core.ContentTypeJSON, `{"token":"raw-token"}`)
	HandleVerifyEmail(d, ctx2)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("replay: status = %d, want 400 (single-use)", rec2.Code)
	}
}

// TestHandleVerifyEmail_ModeA_OptInStampsExistingUser covers updateVerifiedEmail:
// when the user already exists (Mode A immediate creation, ?send_verification=
// true) the token carries no PasswordHash and verify only stamps
// email_verified=true on the live record rather than treating it as a
// username conflict.
func TestHandleVerifyEmail_ModeA_OptInStampsExistingUser(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	if err := d.users.CreateOrUpdate(t.Context(), &core.User{ID: "carol", Email: "carol@example.com"}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	issueRawVerificationToken(t, d, "raw-token", &core.EmailVerificationToken{
		Username: "carol", Email: "carol@example.com", ExpiresAt: time.Now().Add(time.Hour),
	})
	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"token":"raw-token"}`)
	HandleVerifyEmail(d, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	u, _ := d.users.GetByID(t.Context(), "carol")
	if u.Attributes["email_verified"] != "true" {
		t.Error("existing user must be stamped email_verified=true")
	}
}

// TestHandleVerifyEmail_ModeB_UsernameTakenAtVerifyTime covers the Mode B
// conflict branch: the username was claimed by someone else between issue and
// verify. Oracle-safe: collapses to the same verification_invalid as any
// other bad token, never a distinguishing 409.
func TestHandleVerifyEmail_ModeB_UsernameTakenAtVerifyTime(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	pwHash, _ := bcrypt.GenerateFromPassword([]byte("s3cret!!"), bcrypt.DefaultCost)
	issueRawVerificationToken(t, d, "raw-token", &core.EmailVerificationToken{
		Username: "dave", Email: "dave@example.com", PasswordHash: string(pwHash),
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err := d.users.CreateOrUpdate(t.Context(), &core.User{ID: "dave"}); err != nil {
		t.Fatalf("seed conflicting user: %v", err)
	}
	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"token":"raw-token"}`)
	HandleVerifyEmail(d, ctx)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := decodeBody(t, rec)["error"]; got != core.ErrVerificationInvalid {
		t.Fatalf("error = %v, want %s (oracle-safe collapse)", got, core.ErrVerificationInvalid)
	}
}
