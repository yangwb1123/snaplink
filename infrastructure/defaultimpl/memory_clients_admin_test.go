package defaultimpl_test

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

func TestMemoryClientStore_AddGetListUpdate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryClientStore()

	if err := s.Add(ctx, &sso.Client{ID: "c1", Active: true, AllowedScopes: []string{"openid"}}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// Duplicate Add is rejected.
	if err := s.Add(ctx, &sso.Client{ID: "c1"}); !errors.Is(err, sso.ErrClientExists) {
		t.Errorf("duplicate Add = %v, want ErrClientExists", err)
	}
	// nil / empty ID rejected.
	if err := s.Add(ctx, nil); err == nil {
		t.Error("Add(nil) should error")
	}
	if err := s.Add(ctx, &sso.Client{ID: ""}); err == nil {
		t.Error("Add(empty id) should error")
	}

	got, err := s.Get(ctx, "c1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != "c1" {
		t.Errorf("Get = %+v", got)
	}

	// List returns the single client.
	list, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].ID != "c1" {
		t.Errorf("List = %+v", list)
	}

	// Update an existing client.
	if err := s.Update(ctx, &sso.Client{ID: "c1", Active: false, AllowedScopes: []string{"openid", "profile"}}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	updated, _ := s.Get(ctx, "c1")
	if updated.Active || len(updated.AllowedScopes) != 2 {
		t.Errorf("post-update = %+v", updated)
	}

	// Update of an unknown client is rejected.
	if err := s.Update(ctx, &sso.Client{ID: "ghost"}); !errors.Is(err, sso.ErrNoSuchClient) {
		t.Errorf("Update(unknown) = %v, want ErrNoSuchClient", err)
	}
	if err := s.Update(ctx, nil); err == nil {
		t.Error("Update(nil) should error")
	}
}

func TestMemoryClientStore_AddHashesSecret(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryClientStore()
	if err := s.Add(ctx, &sso.Client{ID: "c1", Secret: "plaintext", Active: true, RegistrationAccessToken: "rat-plain"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, _ := s.Get(ctx, "c1")
	if got.Secret == "plaintext" {
		t.Error("secret stored as plaintext, expected bcrypt hash")
	}
	if got.RegistrationAccessToken == "rat-plain" {
		t.Error("registration token stored as plaintext, expected hash")
	}
	// The hashed secret still validates against the original plaintext.
	if err := s.ValidateSecret(ctx, "c1", "plaintext"); err != nil {
		t.Errorf("ValidateSecret with original plaintext: %v", err)
	}
}

func TestMemoryClientStore_RotateSecret(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryClientStore()
	_ = s.Add(ctx, &sso.Client{ID: "c1", Secret: "old", Active: true})

	plaintext, err := s.RotateSecret(ctx, "c1")
	if err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	if plaintext == "" {
		t.Fatal("RotateSecret returned empty plaintext")
	}
	// The new plaintext validates; the old one no longer does.
	if err := s.ValidateSecret(ctx, "c1", plaintext); err != nil {
		t.Errorf("new secret rejected: %v", err)
	}
	if err := s.ValidateSecret(ctx, "c1", "old"); err == nil {
		t.Error("old secret still valid after rotation")
	}

	// Rotating an unknown client is rejected.
	if _, err := s.RotateSecret(ctx, "ghost"); !errors.Is(err, sso.ErrNoSuchClient) {
		t.Errorf("RotateSecret(unknown) = %v, want ErrNoSuchClient", err)
	}
}

func TestMemoryClientStore_ValidateInactiveClient(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryClientStore()
	_ = s.Add(ctx, &sso.Client{ID: "c1", Secret: "sec", Active: false})
	// Correct secret but inactive client → error.
	if err := s.ValidateSecret(ctx, "c1", "sec"); err == nil {
		t.Error("inactive client should fail ValidateSecret")
	}
}

func TestMemoryClientStore_Delete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryClientStore()
	_ = s.Add(ctx, &sso.Client{ID: "c1", Active: true})
	if err := s.Delete(ctx, "c1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, "c1"); !errors.Is(err, sso.ErrNoSuchClient) {
		t.Errorf("after delete = %v", err)
	}
	// Idempotent delete.
	if err := s.Delete(ctx, "c1"); err != nil {
		t.Errorf("Delete(idempotent) = %v", err)
	}
}
