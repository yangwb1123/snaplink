package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func freshClientStore(t *testing.T) *ClientStore {
	t.Helper()
	s, err := NewClientStore(testConfig(t))
	if err != nil {
		t.Fatalf("NewClientStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.db.ExecContext(context.Background(), "TRUNCATE clients"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return s
}

// richClient exercises every column class: scalars, integer-encoded bools,
// BIGINT nanosecond durations, JSON slices, and the JSON attributes map.
func richClient() *sso.Client {
	return &sso.Client{
		ID:                               "c1",
		Secret:                           "s3cr3t-plain",
		Name:                             "Acme",
		RedirectURIs:                     []string{"https://a/cb", "https://b/cb"},
		AllowedScopes:                    []string{"openid", "profile"},
		AllowedAuthenticators:            []string{"password"},
		TokenStrategy:                    "jwt",
		Active:                           true,
		TenantID:                         "t1",
		RequirePKCE:                      true,
		AllowedResources:                 []string{"https://api"},
		AllowedRequestURIs:               []string{"urn:x"},
		PostLogoutRedirectURIs:           []string{"https://a/out"},
		AllowedAuthorizationDetailsTypes: []string{"payment"},
		RefreshTokenTTL:                  72 * time.Hour,
		AccessTokenTTL:                   15 * time.Minute,
		AllowedPKCEMethods:               []string{"S256"},
		RequireSignedRequestObject:       true,
		RequirePAR:                       true,
		DeviceCodeTTL:                    10 * time.Minute,
		DeviceCodePollInterval:           5 * time.Second,
		UserinfoSignedResponseAlg:        "ES256",
		BackchannelLogoutURI:             "https://a/bcl",
		SubjectType:                      "pairwise",
		SectorIdentifierURI:              "https://a/sector",
		FrontchannelLogoutURI:            "https://a/fcl",
		Federation:                       true,
		Attributes:                       map[string]string{"k": "v"},
	}
}

func TestClient_AddGetRoundTripAllColumns(t *testing.T) {
	t.Parallel()
	s := freshClientStore(t)
	ctx := context.Background()
	in := richClient()
	if err := s.Add(ctx, in); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := s.Get(ctx, "c1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Secret is bcrypt-hashed at rest, so it must NOT round-trip as plaintext
	// but MUST verify.
	if got.Secret == "s3cr3t-plain" {
		t.Fatal("secret stored as plaintext — must be bcrypt-hashed at rest")
	}
	if err := s.ValidateSecret(ctx, "c1", "s3cr3t-plain"); err != nil {
		t.Fatalf("ValidateSecret(correct): %v", err)
	}
	// Every non-secret field must survive the 34-column projection.
	if got.Name != in.Name || got.TokenStrategy != in.TokenStrategy || got.TenantID != in.TenantID ||
		!got.Active || !got.RequirePKCE || !got.RequireSignedRequestObject || !got.RequirePAR || !got.Federation {
		t.Fatalf("scalar/bool round-trip mismatch: %+v", got)
	}
	if got.RefreshTokenTTL != in.RefreshTokenTTL || got.AccessTokenTTL != in.AccessTokenTTL ||
		got.DeviceCodeTTL != in.DeviceCodeTTL || got.DeviceCodePollInterval != in.DeviceCodePollInterval {
		t.Fatalf("BIGINT duration round-trip mismatch: %+v", got)
	}
	if len(got.RedirectURIs) != 2 || len(got.AllowedScopes) != 2 || got.AllowedPKCEMethods[0] != "S256" ||
		got.Attributes["k"] != "v" || got.SubjectType != "pairwise" {
		t.Fatalf("JSON column round-trip mismatch: %+v", got)
	}
}

func TestClient_AddDuplicateAndMissing(t *testing.T) {
	t.Parallel()
	s := freshClientStore(t)
	ctx := context.Background()
	if err := s.Add(ctx, &sso.Client{ID: "c1", Secret: "x", Active: true}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := s.Add(ctx, &sso.Client{ID: "c1", Secret: "y"}); !errors.Is(err, sso.ErrClientExists) {
		t.Fatalf("duplicate Add err = %v, want ErrClientExists", err)
	}
	if _, err := s.Get(ctx, "nope"); !errors.Is(err, sso.ErrNoSuchClient) {
		t.Fatalf("Get(missing) err = %v, want ErrNoSuchClient", err)
	}
	if err := s.Update(ctx, &sso.Client{ID: "nope", Secret: "z"}); !errors.Is(err, sso.ErrNoSuchClient) {
		t.Fatalf("Update(missing) err = %v, want ErrNoSuchClient", err)
	}
}

func TestClient_PutUpsertAndUpdate(t *testing.T) {
	t.Parallel()
	s := freshClientStore(t)
	ctx := context.Background()
	// Put creates then overwrites in full.
	if err := s.Put(ctx, &sso.Client{ID: "c1", Secret: "x", Name: "first", Active: true}); err != nil {
		t.Fatalf("Put create: %v", err)
	}
	if err := s.Put(ctx, &sso.Client{ID: "c1", Secret: "x", Name: "second", Active: false}); err != nil {
		t.Fatalf("Put overwrite: %v", err)
	}
	got, _ := s.Get(ctx, "c1")
	if got.Name != "second" || got.Active {
		t.Fatalf("Put did not overwrite in full: %+v", got)
	}
	// Update changes fields on an existing row.
	got.Name = "third"
	if err := s.Update(ctx, got); err != nil {
		t.Fatalf("Update: %v", err)
	}
	again, _ := s.Get(ctx, "c1")
	if again.Name != "third" {
		t.Fatalf("Update did not apply: %+v", again)
	}
}

func TestClient_ValidateSecretInactiveAndWrong(t *testing.T) {
	t.Parallel()
	s := freshClientStore(t)
	ctx := context.Background()
	if err := s.Add(ctx, &sso.Client{ID: "c1", Secret: "right", Active: true}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := s.ValidateSecret(ctx, "c1", "wrong"); err == nil {
		t.Fatal("ValidateSecret(wrong) must fail")
	}
	// Deactivate → must refuse even with the right secret.
	if err := s.Put(ctx, &sso.Client{ID: "c1", Secret: "right", Active: false}); err != nil {
		t.Fatalf("Put inactive: %v", err)
	}
	if err := s.ValidateSecret(ctx, "c1", "right"); err == nil {
		t.Fatal("ValidateSecret on inactive client must fail")
	}
}

func TestClient_ListByTenantIsolationAndRotate(t *testing.T) {
	t.Parallel()
	s := freshClientStore(t)
	ctx := context.Background()
	for _, c := range []*sso.Client{
		{ID: "c1", Secret: "x", TenantID: "t1", Active: true},
		{ID: "c2", Secret: "x", TenantID: "t1", Active: true},
		{ID: "c3", Secret: "x", TenantID: "t2", Active: true},
		{ID: "c4", Secret: "x", Active: true}, // no tenant — excluded from the partial index
	} {
		if err := s.Add(ctx, c); err != nil {
			t.Fatalf("Add %s: %v", c.ID, err)
		}
	}
	t1, err := s.ListByTenant(ctx, "t1")
	if err != nil || len(t1) != 2 {
		t.Fatalf("ListByTenant(t1) = %d clients (err %v), want 2", len(t1), err)
	}
	all, _ := s.List(ctx)
	if len(all) != 4 {
		t.Fatalf("List = %d, want 4", len(all))
	}
	n, _, err := s.Stats(ctx)
	if err != nil || n != 4 {
		t.Fatalf("Stats count = %d (err %v), want 4", n, err)
	}

	// RotateSecret returns a new plaintext that validates; the old one no longer does.
	plain, err := s.RotateSecret(ctx, "c1")
	if err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	if err := s.ValidateSecret(ctx, "c1", plain); err != nil {
		t.Fatalf("rotated secret must validate: %v", err)
	}
	if err := s.ValidateSecret(ctx, "c1", "x"); err == nil {
		t.Fatal("old secret must no longer validate after rotation")
	}

	// Delete is idempotent.
	if err := s.Delete(ctx, "c1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := s.Delete(ctx, "c1"); err != nil {
		t.Fatalf("Delete (idempotent): %v", err)
	}
}
