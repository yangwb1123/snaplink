package adminuser

import (
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

type passwordPolicyAdminUserDeps struct {
	*testDeps
	policy spi.PasswordPolicyValidator
}

func (d *passwordPolicyAdminUserDeps) PasswordPolicyValidator() spi.PasswordPolicyValidator {
	return d.policy
}

func TestHandleAdminCreateUser_RejectsConfiguredPolicyBeforeWrites(t *testing.T) {
	t.Parallel()
	d := &passwordPolicyAdminUserDeps{
		testDeps: newTestDeps(),
		policy:   spi.NewPasswordPolicyValidator(spi.PasswordPolicyConfig{MinLength: 12}),
	}
	ctx, rec := newCtx("POST", "/api/v1/admin/local-users", "", `{"username":"alice","email":"alice@example.com","password":"Abcdefg1"}`)
	HandleAdminCreateUser(d, ctx)
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), core.ErrInvalidRequest) {
		t.Fatalf("error = %s, want generic invalid-request error", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "Abcdefg1") {
		t.Fatalf("response leaked candidate password: %s", rec.Body.String())
	}
	users, err := d.users.List(t.Context())
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("policy rejection persisted %d users", len(users))
	}
}
