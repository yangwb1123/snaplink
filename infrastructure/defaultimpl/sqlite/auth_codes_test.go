package sqlite_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	"github.com/yangwb1123/snaplink/platform/migrate"
	"github.com/yangwb1123/snaplink/protocols/oauth"

	_ "modernc.org/sqlite"
)

// TestSQLiteAuthCode_AuthContextRoundTrip proves the RFC 9068 §2.2
// authentication-context fields (AuthTime, AuthMethods/amr, ACR, Resources,
// AuthorizationDetails, SID) that issueAuthCode (interfaces/sso/server_oauth.go)
// populates at /auth/login survive a fresh-schema Issue and are returned by
// Consume — the SQLite store previously dropped all six silently, unlike the
// memory and Redis backends.
func TestSQLiteAuthCode_AuthContextRoundTrip(t *testing.T) {
	t.Parallel()
	st, err := sqlite.NewAuthCodeStore(freshSharedDSN(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// Truncate to seconds: AuthTime round-trips via UnixNano, but the test
	// only needs to prove propagation, not sub-second precision.
	authTime := time.Now().Add(-90 * time.Second).Truncate(time.Second)
	in := &oauth.AuthCode{
		UserID: "u-1", ClientID: "web", ExpiresAt: time.Now().Add(time.Minute),
		AuthTime:             authTime,
		AuthMethods:          []string{"pwd", "otp"},
		ACR:                  "urn:mace:incommon:iap:silver",
		Resources:            []string{"https://api.example.com"},
		AuthorizationDetails: json.RawMessage(`[{"type":"payment_initiation"}]`),
		SID:                  "sid-abc123",
	}
	if err := st.Issue(context.Background(), "code-ctx", in); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	out, err := st.Consume(context.Background(), "code-ctx")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if !out.AuthTime.Equal(authTime) {
		t.Errorf("AuthTime = %v, want %v", out.AuthTime, authTime)
	}
	if len(out.AuthMethods) != 2 || out.AuthMethods[0] != "pwd" || out.AuthMethods[1] != "otp" {
		t.Errorf("AuthMethods = %v, want [pwd otp]", out.AuthMethods)
	}
	if out.ACR != "urn:mace:incommon:iap:silver" {
		t.Errorf("ACR = %q", out.ACR)
	}
	if len(out.Resources) != 1 || out.Resources[0] != "https://api.example.com" {
		t.Errorf("Resources = %v", out.Resources)
	}
	if string(out.AuthorizationDetails) != `[{"type":"payment_initiation"}]` {
		t.Errorf("AuthorizationDetails = %s", out.AuthorizationDetails)
	}
	if out.SID != "sid-abc123" {
		t.Errorf("SID = %q", out.SID)
	}
}

// TestSQLiteAuthCode_AuthContextDefaultsEmpty proves a code issued without
// any of the six RFC 9068 auth-context fields (the common case — most
// providers don't set AuthorizationDetails/SID at all) round-trips them as
// zero values rather than picking up a stray column default.
func TestSQLiteAuthCode_AuthContextDefaultsEmpty(t *testing.T) {
	t.Parallel()
	st, err := sqlite.NewAuthCodeStore(freshSharedDSN(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	_ = st.Issue(context.Background(), "code-bare", &oauth.AuthCode{
		UserID: "u", ClientID: "c", ExpiresAt: time.Now().Add(time.Minute),
	})
	out, err := st.Consume(context.Background(), "code-bare")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if !out.AuthTime.IsZero() {
		t.Errorf("AuthTime = %v, want zero", out.AuthTime)
	}
	if len(out.AuthMethods) != 0 {
		t.Errorf("AuthMethods = %v, want empty", out.AuthMethods)
	}
	if out.ACR != "" {
		t.Errorf("ACR = %q, want empty", out.ACR)
	}
	if len(out.Resources) != 0 {
		t.Errorf("Resources = %v, want empty", out.Resources)
	}
	if out.AuthorizationDetails != nil {
		t.Errorf("AuthorizationDetails = %s, want nil", out.AuthorizationDetails)
	}
	if out.SID != "" {
		t.Errorf("SID = %q, want empty", out.SID)
	}
}

// legacyAuthCodeV2DDL is the pre-v3 baseline (v1 columns + v2's
// confirmation_jkt) — a database provisioned before the RFC 9068
// auth-context columns existed. Used to prove the v3 additive migration
// backfills all six columns with their zero-value defaults on pre-existing
// rows while leaving every other column untouched.
const legacyAuthCodeV2DDL = `
CREATE TABLE auth_codes (
    code                  TEXT    PRIMARY KEY,
    user_id               TEXT    NOT NULL,
    client_id             TEXT    NOT NULL,
    redirect_uri          TEXT    NOT NULL DEFAULT '',
    scopes                TEXT    NOT NULL DEFAULT '[]',
    nonce                 TEXT    NOT NULL DEFAULT '',
    provider              TEXT    NOT NULL DEFAULT '',
    attributes            TEXT    NOT NULL DEFAULT '{}',
    code_challenge        TEXT    NOT NULL DEFAULT '',
    code_challenge_method TEXT    NOT NULL DEFAULT '',
    confirmation_jkt      TEXT    NOT NULL DEFAULT '',
    expires_at            INTEGER NOT NULL
);`

// TestSQLiteAuthCode_AuthContextAdditiveMigration proves the v4 migration
// upgrades a v2-schema pre-existing database (missing auth_time/amr/acr/
// resources/authorization_details/sid) without losing the pre-existing row
// or its other columns, and that a NEW code issued after the upgrade
// persists the new fields normally.
func TestSQLiteAuthCode_AuthContextAdditiveMigration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "ac-legacy.db")

	// Seed a pre-v3 database directly (bypassing the store) so it looks
	// exactly like a database created before the auth-context columns
	// existed: the v2 12-column schema, none of the new columns, and the
	// schema version table stamped at v2 (matches a real upgrade — the
	// v1+v2 boot that created this table ran before v3 was added).
	seed, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := seed.Exec(legacyAuthCodeV2DDL); err != nil {
		t.Fatalf("legacy ddl: %v", err)
	}
	now := time.Now()
	if _, err := seed.Exec(
		`INSERT INTO auth_codes (code, user_id, client_id, redirect_uri, code_challenge, expires_at)
		 VALUES ('legacy-code', 'u', 'c', 'https://app/cb', 'chal-1', ?)`,
		now.Add(time.Minute).UnixNano(),
	); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	if err := migrate.Run(ctx, seed, "auth_codes", []migrate.Migration{
		{Version: 1, Name: "baseline", SQL: `SELECT 1`},
		{Version: 2, Name: "auth_code_dpop_binding", SQL: `SELECT 1`},
	}); err != nil {
		t.Fatalf("stamp v2: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("close seed: %v", err)
	}

	// NewAuthCodeStore reopens the SAME file and runs the real migration
	// set — exactly what a pre-upgrade deployment's next boot does.
	st, err := sqlite.NewAuthCodeStore(dsn)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if v, _ := migrate.CurrentVersion(ctx, st.DB(), "auth_codes"); v != 4 {
		t.Errorf("version = %d, want 4", v)
	}

	// The legacy row survives, its pre-existing columns intact, and the six
	// new columns default to their additive zero values (0 / '[]' / '').
	out, err := st.Consume(ctx, "legacy-code")
	if err != nil {
		t.Fatalf("Consume legacy row: %v", err)
	}
	if out.UserID != "u" || out.ClientID != "c" || out.RedirectURI != "https://app/cb" || out.CodeChallenge != "chal-1" {
		t.Errorf("legacy row's pre-existing columns lost: %+v", out)
	}
	if !out.AuthTime.IsZero() {
		t.Errorf("legacy row AuthTime = %v, want zero (additive default)", out.AuthTime)
	}
	if len(out.AuthMethods) != 0 {
		t.Errorf("legacy row AuthMethods = %v, want empty", out.AuthMethods)
	}
	if out.ACR != "" {
		t.Errorf("legacy row ACR = %q, want empty", out.ACR)
	}
	if len(out.Resources) != 0 {
		t.Errorf("legacy row Resources = %v, want empty", out.Resources)
	}
	if out.AuthorizationDetails != nil {
		t.Errorf("legacy row AuthorizationDetails = %s, want nil", out.AuthorizationDetails)
	}
	if out.SID != "" {
		t.Errorf("legacy row SID = %q, want empty", out.SID)
	}

	// A NEW code on the migrated schema persists the new fields normally.
	authTime := now.Add(-time.Minute).Truncate(time.Second)
	if err := st.Issue(ctx, "new-code", &oauth.AuthCode{
		UserID: "u", ClientID: "c", ExpiresAt: now.Add(time.Minute),
		AuthTime: authTime, AuthMethods: []string{"pwd"}, ACR: "acr1",
		Resources: []string{"res1"}, SID: "sid1",
	}); err != nil {
		t.Fatalf("Issue new: %v", err)
	}
	out2, err := st.Consume(ctx, "new-code")
	if err != nil {
		t.Fatalf("Consume new: %v", err)
	}
	if !out2.AuthTime.Equal(authTime) || out2.ACR != "acr1" || out2.SID != "sid1" {
		t.Errorf("new row auth-context lost: %+v", out2)
	}
}
