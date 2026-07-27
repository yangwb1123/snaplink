package rs_test

import (
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
)

func TestCheckScope(t *testing.T) {
	t.Parallel()
	claims := &rs.Claims{Scope: "orders:read orders:write"}

	if err := rs.CheckScope(claims, "orders:read"); err != nil {
		t.Errorf("CheckScope(orders:read) = %v, want nil", err)
	}
	if err := rs.CheckScope(claims, "orders:read", "orders:write"); err != nil {
		t.Errorf("CheckScope(both) = %v, want nil", err)
	}
	err := rs.CheckScope(claims, "orders:read", "orders:delete")
	if !errors.Is(err, rs.ErrInsufficientScope) {
		t.Fatalf("CheckScope(missing) = %v, want ErrInsufficientScope", err)
	}
}

func TestCheckAnyScope(t *testing.T) {
	t.Parallel()
	claims := &rs.Claims{Scope: "orders:read"}

	if err := rs.CheckAnyScope(claims, "orders:admin", "orders:read"); err != nil {
		t.Errorf("CheckAnyScope = %v, want nil", err)
	}
	if err := rs.CheckAnyScope(claims, "orders:admin", "orders:delete"); !errors.Is(err, rs.ErrInsufficientScope) {
		t.Errorf("CheckAnyScope(none present) = %v, want ErrInsufficientScope", err)
	}
	if err := rs.CheckAnyScope(claims); !errors.Is(err, rs.ErrInsufficientScope) {
		t.Errorf("CheckAnyScope(empty list) = %v, want ErrInsufficientScope (fail closed)", err)
	}
}

func TestHasScope_NilClaims(t *testing.T) {
	t.Parallel()
	if rs.HasScope(nil, "orders:read") {
		t.Error("HasScope(nil, ...) = true, want false (fail closed)")
	}
}

func TestRequireSubject(t *testing.T) {
	t.Parallel()
	sub, err := rs.RequireSubject(&rs.Claims{Subject: "user-1"})
	if err != nil || sub != "user-1" {
		t.Fatalf("RequireSubject = (%q, %v), want (user-1, nil)", sub, err)
	}
	if _, err := rs.RequireSubject(&rs.Claims{}); !errors.Is(err, rs.ErrSubjectMissing) {
		t.Fatalf("RequireSubject(no sub) = %v, want ErrSubjectMissing", err)
	}
	if _, err := rs.RequireSubject(nil); !errors.Is(err, rs.ErrSubjectMissing) {
		t.Fatalf("RequireSubject(nil) = %v, want ErrSubjectMissing", err)
	}
}
