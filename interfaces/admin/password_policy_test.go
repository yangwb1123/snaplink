package admin

import (
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystorecredential"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

type passwordPolicyAdminDeps struct {
	*gcTestDeps
	passwords *memorystorecredential.MemoryPasswordCredentialStore
	policy    spi.PasswordPolicyValidator
}

func (d *passwordPolicyAdminDeps) PasswordCredentialStore() core.PasswordCredentialStore {
	return d.passwords
}

func (d *passwordPolicyAdminDeps) PasswordPolicyValidator() spi.PasswordPolicyValidator {
	return d.policy
}

func TestHandleAdminResetUserPassword_RejectsConfiguredPolicy(t *testing.T) {
	t.Parallel()
	passwords := memorystorecredential.NewMemoryPasswordCredentialStore()
	if err := passwords.SetPassword(t.Context(), "user-1", "old-password1"); err != nil {
		t.Fatalf("seed password: %v", err)
	}
	d := &passwordPolicyAdminDeps{
		gcTestDeps: newGCTestDeps(),
		passwords:  passwords,
		policy:     spi.NewPasswordPolicyValidator(spi.PasswordPolicyConfig{MinLength: 12}),
	}
	ctx, rec := gcCtx("POST", "/api/v1/admin/users/user-1/password", "admin-1", "user-1", `{"new_password":"short1"}`)
	HandleAdminResetUserPassword(d, ctx)
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), core.ErrPasswordPolicyViolation) {
		t.Fatalf("error = %s, want generic password-policy error", rec.Body.String())
	}
	if containsPassword(rec.Body.String(), "short1") {
		t.Fatalf("response leaked candidate password: %s", rec.Body.String())
	}
	if err := passwords.VerifyPassword(t.Context(), "user-1", "old-password1"); err != nil {
		t.Fatalf("rejected reset changed stored password: %v", err)
	}
}

func containsPassword(body, password string) bool {
	return len(password) > 0 && strings.Contains(body, password)
}
