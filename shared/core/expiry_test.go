package core

import (
	"testing"
	"time"
)

func TestDeviceSecretIsExpired(t *testing.T) {
	t.Parallel()

	now := time.Now()

	tests := []struct {
		name     string
		secret   *DeviceSecret
		expected bool
	}{
		{name: "not expired", secret: &DeviceSecret{ExpiresAt: now.Add(time.Hour)}, expected: false},
		{name: "expired", secret: &DeviceSecret{ExpiresAt: now.Add(-time.Hour)}, expected: true},
		{name: "zero time", secret: &DeviceSecret{}, expected: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.secret.IsExpired()
			if got != tc.expected {
				t.Errorf("DeviceSecret.IsExpired() = %v, want %v (expiresAt=%v)", got, tc.expected, tc.secret.ExpiresAt)
			}
		})
	}
}

func TestEmailChangeTokenIsExpired(t *testing.T) {
	t.Parallel()

	now := time.Now()

	tests := []struct {
		name     string
		token    *EmailChangeToken
		expected bool
	}{
		{name: "not expired", token: &EmailChangeToken{ExpiresAt: now.Add(time.Hour)}, expected: false},
		{name: "expired", token: &EmailChangeToken{ExpiresAt: now.Add(-time.Hour)}, expected: true},
		{name: "zero time", token: &EmailChangeToken{}, expected: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.token.IsExpired()
			if got != tc.expected {
				t.Errorf("EmailChangeToken.IsExpired() = %v, want %v (expiresAt=%v)", got, tc.expected, tc.token.ExpiresAt)
			}
		})
	}
}

func TestPasswordResetTokenIsExpired(t *testing.T) {
	t.Parallel()

	now := time.Now()

	tests := []struct {
		name     string
		token    *PasswordResetToken
		expected bool
	}{
		{name: "not expired", token: &PasswordResetToken{ExpiresAt: now.Add(time.Hour)}, expected: false},
		{name: "expired", token: &PasswordResetToken{ExpiresAt: now.Add(-time.Hour)}, expected: true},
		{name: "zero time", token: &PasswordResetToken{}, expected: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.token.IsExpired()
			if got != tc.expected {
				t.Errorf("PasswordResetToken.IsExpired() = %v, want %v (expiresAt=%v)", got, tc.expected, tc.token.ExpiresAt)
			}
		})
	}
}

func TestInvitationIsExpired(t *testing.T) {
	t.Parallel()

	now := time.Now()

	tests := []struct {
		name     string
		inv      *Invitation
		expected bool
	}{
		{name: "not expired", inv: &Invitation{ExpiresAt: now.Add(time.Hour)}, expected: false},
		{name: "expired", inv: &Invitation{ExpiresAt: now.Add(-time.Hour)}, expected: true},
		{name: "zero time", inv: &Invitation{}, expected: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.inv.IsExpired()
			if got != tc.expected {
				t.Errorf("Invitation.IsExpired() = %v, want %v (expiresAt=%v)", got, tc.expected, tc.inv.ExpiresAt)
			}
		})
	}
}
