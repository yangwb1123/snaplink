package core

import (
	"errors"
	"testing"
)

func TestSentinelErrors(t *testing.T) {
	t.Parallel()

	// Verify each sentinel is a distinct error.
	errs := []struct {
		name string
		err  error
	}{
		{"ErrClientExists", ErrClientExists},
		{"ErrNoSuchClient", ErrNoSuchClient},
		{"ErrUserExists", ErrUserExists},
		{"ErrNoSuchUser", ErrNoSuchUser},
		{"ErrSessionNotFound", ErrSessionNotFound},
		{"ErrUnsupportedOperation", ErrUnsupportedOperation},
		{"ErrNoConsentGrant", ErrNoConsentGrant},
		{"ErrPasswordMismatch", ErrPasswordMismatch},
		{"ErrDeviceSecretNotFound", ErrDeviceSecretNotFound},
		{"ErrResetTokenNotFound", ErrResetTokenNotFound},
		{"ErrEmailChangeTokenNotFound", ErrEmailChangeTokenNotFound},
	}

	for i, a := range errs {
		for j, b := range errs {
			if i == j {
				continue
			}
			if errors.Is(a.err, b.err) {
				t.Errorf("%s should not be %s", a.name, b.name)
			}
		}
	}

	// Verify each sentinel is self-identifying via Is.
	for _, e := range errs {
		if !errors.Is(e.err, e.err) {
			t.Errorf("%s should Is itself", e.name)
		}
	}
}

func TestSentinelErrorMessages(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err    error
		prefix string
	}{
		{ErrClientExists, "sso: client already exists"},
		{ErrNoSuchClient, "sso: client not found"},
		{ErrUserExists, "sso: user already exists"},
		{ErrNoSuchUser, "sso: user not found"},
		{ErrSessionNotFound, "sso: session not found"},
		{ErrUnsupportedOperation, "sso: operation not supported by backend"},
		{ErrNoConsentGrant, "sso: no consent grant found"},
		{ErrPasswordMismatch, "sso: password mismatch"},
		{ErrDeviceSecretNotFound, "sso: device secret not found or expired"},
		{ErrResetTokenNotFound, "sso: password reset token not found or expired"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.err.Error(), func(t *testing.T) {
			t.Parallel()
			if tc.err.Error() != tc.prefix {
				t.Errorf("got %q, want %q", tc.err.Error(), tc.prefix)
			}
		})
	}
}
