package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/migrate"
	"github.com/yangwb1123/snaplink/protocols/oauth/oauthspi"
)

// freshOAuthStore opens a shared-pool store for the named namespace and
// truncates its tables so every test starts from an empty schema. Tests run
// sequentially (no t.Parallel) because they share one test database.
func freshOAuthStore(t *testing.T) (*sql.DB, Dialect) {
	t.Helper()
	cfg := testConfig(t)
	db, err := Open(cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, _ = db.ExecContext(context.Background(), `TRUNCATE auth_codes`)
	_, _ = db.ExecContext(context.Background(), `TRUNCATE refresh_tokens, refresh_token_families, refresh_rotation_windows`)
	_, _ = db.ExecContext(context.Background(), `TRUNCATE device_codes`)
	_, _ = db.ExecContext(context.Background(), `TRUNCATE par_requests`)
	_, _ = db.ExecContext(context.Background(), `TRUNCATE refresh_grace_cache`)
	return db, cfg.Dialect
}

// assertSentinel is the shared negative-path check: the store returned the
// contract sentinel and did NOT leak the driver's sql.ErrNoRows.
func assertSentinel(t *testing.T, err, sentinel error) {
	t.Helper()
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel %v", err, sentinel)
	}
	if errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("driver error sql.ErrNoRows leaked through: %v", err)
	}
}

func TestOAuthStores_MigrateIdempotentAndMaxVersions(t *testing.T) {
	db, dialect := freshOAuthStore(t)
	ctx := context.Background()
	// Second Run on every namespace is a no-op and CheckSchema at the binary
	// max passes while a forward-migrated DB is rejected.
	for _, ns := range []struct {
		name  string
		migs  []migrate.Migration
		maxFn func() int
		want  int
	}{
		{"auth_codes", authCodeMigrations, AuthCodesMaxVersion, 1},
		{"refresh_tokens", refreshTokenMigrations, RefreshTokensMaxVersion, 2},
		{"device_codes", deviceCodeMigrations, DeviceCodesMaxVersion, 1},
		{"par", parMigrations, PARMaxVersion, 1},
		{"refresh_grace", refreshGraceMigrations, RefreshGraceMaxVersion, 1},
	} {
		if err := Run(ctx, db, ns.name, ns.migs, dialect); err != nil {
			t.Fatalf("first Run(%s): %v", ns.name, err)
		}
		if err := Run(ctx, db, ns.name, ns.migs, dialect); err != nil {
			t.Fatalf("second Run(%s): %v", ns.name, err)
		}
		if v := ns.maxFn(); v != ns.want {
			t.Fatalf("%s MaxVersion = %d, want %d", ns.name, v, ns.want)
		}
		if err := CheckSchema(ctx, db, ns.name, ns.maxFn()); err != nil {
			t.Fatalf("CheckSchema(%s) at binary max: %v", ns.name, err)
		}
		if err := CheckSchema(ctx, db, ns.name, 0); err == nil {
			t.Fatalf("CheckSchema(%s) must reject a DB ahead of the binary", ns.name)
		}
	}
}

func TestAuthCodeStore_RoundTripAndSingleUse(t *testing.T) {
	db, dialect := freshOAuthStore(t)
	ctx := context.Background()
	s, err := NewAuthCodeStoreWithDB(db, dialect)
	if err != nil {
		t.Fatalf("NewAuthCodeStoreWithDB: %v", err)
	}
	authTime := time.Now().Add(-90 * time.Second).Truncate(time.Second)
	in := &oauthspi.AuthCode{
		UserID: "u-1", ClientID: "web", RedirectURI: "https://rp/cb",
		ExpiresAt: time.Now().Add(time.Minute),
		Scopes:    []string{"openid", "profile"}, Nonce: "n-1", Provider: "pwd",
		Attributes: map[string]string{"k": "v"},
		AuthTime:   authTime, AuthMethods: []string{"pwd", "otp"}, ACR: "acr-silver",
		Resources:            []string{"https://api.example.com"},
		AuthorizationDetails: json.RawMessage(`[{"type":"payment_initiation"}]`),
		SID:                  "sid-abc", ConfirmationJKT: "jkt-1",
		CodeChallenge: "chal", CodeChallengeMethod: "S256",
		RequestedClaims: json.RawMessage(`{"id_token":{"email":null}}`),
	}
	if err := s.Issue(ctx, "code-1", in); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	out, err := s.Consume(ctx, "code-1")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if out.UserID != "u-1" || out.ClientID != "web" || out.RedirectURI != "https://rp/cb" {
		t.Fatalf("base fields lost: %+v", out)
	}
	if len(out.Scopes) != 2 || out.Scopes[0] != "openid" || out.Nonce != "n-1" || out.Provider != "pwd" {
		t.Fatalf("scopes/nonce/provider lost: %+v", out)
	}
	if out.Attributes["k"] != "v" {
		t.Fatalf("attributes lost: %+v", out.Attributes)
	}
	if !out.AuthTime.Equal(authTime) || len(out.AuthMethods) != 2 || out.ACR != "acr-silver" {
		t.Fatalf("auth context lost: %+v", out)
	}
	if len(out.Resources) != 1 || string(out.AuthorizationDetails) != `[{"type":"payment_initiation"}]` ||
		out.SID != "sid-abc" || out.ConfirmationJKT != "jkt-1" {
		t.Fatalf("rar/sid/jkt lost: %+v", out)
	}
	if out.CodeChallenge != "chal" || out.CodeChallengeMethod != "S256" {
		t.Fatalf("PKCE columns lost: %+v", out)
	}
	if string(out.RequestedClaims) != `{"id_token":{"email":null}}` {
		t.Fatalf("requested_claims lost: %s", out.RequestedClaims)
	}
	// Single-use: second consume is plain not-found, not a driver error.
	_, err = s.Consume(ctx, "code-1")
	assertSentinel(t, err, oauthspi.ErrAuthCodeNotFound)
}

func TestAuthCodeStore_EmptySentinelsRoundTrip(t *testing.T) {
	db, dialect := freshOAuthStore(t)
	ctx := context.Background()
	s, err := NewAuthCodeStoreWithDB(db, dialect)
	if err != nil {
		t.Fatalf("NewAuthCodeStoreWithDB: %v", err)
	}
	if err := s.Issue(ctx, "code-bare", &oauthspi.AuthCode{
		UserID: "u", ClientID: "c", ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	out, err := s.Consume(ctx, "code-bare")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if !out.AuthTime.IsZero() || len(out.AuthMethods) != 0 || out.ACR != "" ||
		len(out.Resources) != 0 || out.AuthorizationDetails != nil || out.SID != "" ||
		out.CodeChallenge != "" || out.RequestedClaims != nil || out.ConfirmationJKT != "" {
		t.Fatalf("empty sentinels not preserved: %+v", out)
	}
}

func TestAuthCodeStore_ExpiredCollapsesToNotFound(t *testing.T) {
	db, dialect := freshOAuthStore(t)
	ctx := context.Background()
	s, err := NewAuthCodeStoreWithDB(db, dialect)
	if err != nil {
		t.Fatalf("NewAuthCodeStoreWithDB: %v", err)
	}
	if err := s.Issue(ctx, "code-stale", &oauthspi.AuthCode{
		UserID: "u", ClientID: "c", ExpiresAt: time.Now().Add(-time.Second),
	}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_, err = s.Consume(ctx, "code-stale")
	assertSentinel(t, err, oauthspi.ErrAuthCodeNotFound)
	// The expired row was deleted by the consume statement — no residue.
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_codes`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("expired row residue: n=%d err=%v", n, err)
	}
}

func TestAuthCodeStore_ConcurrentConsumeSingleWinner(t *testing.T) {
	db, dialect := freshOAuthStore(t)
	ctx := context.Background()
	s, err := NewAuthCodeStoreWithDB(db, dialect)
	if err != nil {
		t.Fatalf("NewAuthCodeStoreWithDB: %v", err)
	}
	if err := s.Issue(ctx, "code-race", &oauthspi.AuthCode{
		UserID: "u", ClientID: "c", ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	var (
		wg      sync.WaitGroup
		winners atomicInt
	)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := s.Consume(ctx, "code-race")
			if err == nil && out != nil {
				winners.add(1)
			} else {
				assertSentinel(t, err, oauthspi.ErrAuthCodeNotFound)
			}
		}()
	}
	wg.Wait()
	if winners.load() != 1 {
		t.Fatalf("winners = %d, want exactly 1", winners.load())
	}
}

func TestAuthCodeStore_OpaqueLookupKeysAndRotation(t *testing.T) {
	db, dialect := freshOAuthStore(t)
	ctx := context.Background()
	s, err := NewAuthCodeStoreWithDB(db, dialect)
	if err != nil {
		t.Fatalf("NewAuthCodeStoreWithDB: %v", err)
	}
	current := []byte("0123456789abcdef0123456789abcdef")
	previous := []byte("abcdef0123456789abcdef0123456789")
	s.SetLookupHMACKeys(current)
	if err := s.Issue(ctx, "code-hmac", &oauthspi.AuthCode{
		UserID: "u", ClientID: "c", ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// The raw code is never stored; only the h1: lookup key is.
	var stored string
	if err := db.QueryRowContext(ctx, `SELECT code FROM auth_codes`).Scan(&stored); err != nil {
		t.Fatalf("read stored code: %v", err)
	}
	if stored == "code-hmac" || !strings.HasPrefix(stored, "h1:") {
		t.Fatalf("raw code persisted: %q", stored)
	}
	// Rotation: reads with the previous key (and legacy plaintext) still work.
	s.SetLookupHMACKeys([]byte("new-key-0123456789abcdef0123456789ab"), previous)
	out, err := s.Consume(ctx, "code-hmac")
	if err != nil || out.UserID != "u" {
		t.Fatalf("previous-key read failed: out=%+v err=%v", out, err)
	}
	// Legacy plaintext fallback: a raw row written with nil keys is readable.
	s2, err := NewAuthCodeStoreWithDB(db, dialect)
	if err != nil {
		t.Fatalf("NewAuthCodeStoreWithDB: %v", err)
	}
	if err := s2.Issue(ctx, "code-plain", &oauthspi.AuthCode{
		UserID: "u", ClientID: "c", ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("Issue plain: %v", err)
	}
	s2.SetLookupHMACKeys(current)
	if _, err := s2.Consume(ctx, "code-plain"); err != nil {
		t.Fatalf("legacy plaintext read failed: %v", err)
	}
}

func TestRefreshTokenStore_RotationAndReuseDetection(t *testing.T) {
	db, dialect := freshOAuthStore(t)
	ctx := context.Background()
	s, err := NewRefreshTokenStoreWithDB(db, dialect)
	if err != nil {
		t.Fatalf("NewRefreshTokenStoreWithDB: %v", err)
	}
	issue := func(token, family string, expiresAt time.Time) {
		t.Helper()
		if err := s.Issue(ctx, token, &oauthspi.RefreshToken{
			UserID: "u-1", ClientID: "c-1", Provider: "pwd",
			Scopes: []string{"openid"}, IssuedAt: time.Now(), ExpiresAt: expiresAt,
			FamilyID: family, JTI: "jti-1", Generation: 1,
		}); err != nil {
			t.Fatalf("Issue(%s): %v", token, err)
		}
	}
	expires := time.Now().Add(time.Hour)
	issue("rt-leaf", "fam-1", expires)

	out, err := s.Consume(ctx, "rt-leaf")
	if err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if out.FamilyID != "fam-1" || out.JTI != "jti-1" || out.Generation != 1 ||
		out.Provider != "pwd" || len(out.Scopes) != 1 {
		t.Fatalf("rotated record lost fields: %+v", out)
	}
	// Replay of the consumed leaf is a reuse signal carrying the family id.
	info, err := s.Consume(ctx, "rt-leaf")
	assertSentinel(t, err, oauthspi.ErrRefreshTokenReused)
	if info == nil || info.FamilyID != "fam-1" {
		t.Fatalf("reuse info = %+v, want FamilyID fam-1", info)
	}
	// Family kill: DeleteFamily removes active siblings AND the ledger, so a
	// post-kill Consume is plain not-found, not a stale reuse signal.
	issue("rt-sibling", "fam-1", expires)
	killed, err := s.DeleteFamily(ctx, "fam-1")
	if err != nil || killed != 1 {
		t.Fatalf("DeleteFamily = (%d, %v), want (1, nil)", killed, err)
	}
	_, err = s.Consume(ctx, "rt-sibling")
	assertSentinel(t, err, oauthspi.ErrRefreshTokenNotFound)
	_, err = s.Consume(ctx, "rt-leaf")
	assertSentinel(t, err, oauthspi.ErrRefreshTokenNotFound)
	// Unknown family DeleteFamily is idempotent.
	if n, err := s.DeleteFamily(ctx, "fam-1"); err != nil || n != 0 {
		t.Fatalf("DeleteFamily unknown = (%d, %v), want (0, nil)", n, err)
	}
}

func TestRefreshTokenStore_UnknownAndExpiredCollapse(t *testing.T) {
	db, dialect := freshOAuthStore(t)
	ctx := context.Background()
	s, err := NewRefreshTokenStoreWithDB(db, dialect)
	if err != nil {
		t.Fatalf("NewRefreshTokenStoreWithDB: %v", err)
	}
	_, err = s.Consume(ctx, "rt-never-issued")
	assertSentinel(t, err, oauthspi.ErrRefreshTokenNotFound)
	if err := s.Issue(ctx, "rt-stale", &oauthspi.RefreshToken{
		UserID: "u", ClientID: "c", IssuedAt: time.Now(),
		ExpiresAt: time.Now().Add(-time.Second), FamilyID: "fam-stale",
	}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_, err = s.Consume(ctx, "rt-stale")
	assertSentinel(t, err, oauthspi.ErrRefreshTokenNotFound)
	// Reuse-path ledger lookup has no expiry filter (SQLite parity): an
	// expired-but-unreaped consumed token still trips reuse detection.
	if _, err := s.Consume(ctx, "rt-stale"); !errors.Is(err, oauthspi.ErrRefreshTokenReused) {
		t.Fatalf("expired consumed token replay = %v, want ErrRefreshTokenReused", err)
	}
}

func TestRefreshTokenStore_InspectDeleteAndCount(t *testing.T) {
	db, dialect := freshOAuthStore(t)
	ctx := context.Background()
	s, err := NewRefreshTokenStoreWithDB(db, dialect)
	if err != nil {
		t.Fatalf("NewRefreshTokenStoreWithDB: %v", err)
	}
	issue := func(token, user, client, family string) {
		t.Helper()
		if err := s.Issue(ctx, token, &oauthspi.RefreshToken{
			UserID: user, ClientID: client, IssuedAt: time.Now(),
			ExpiresAt: time.Now().Add(time.Hour), FamilyID: family,
		}); err != nil {
			t.Fatalf("Issue(%s): %v", token, err)
		}
	}
	issue("rt-a", "u1", "c1", "fam-a")
	issue("rt-b", "u1", "c2", "fam-b")
	issue("rt-c", "u2", "c1", "fam-c")

	// Inspect is non-destructive.
	got, err := s.Inspect(ctx, "rt-a")
	if err != nil || got.UserID != "u1" {
		t.Fatalf("Inspect = (%+v, %v)", got, err)
	}
	if _, err := s.Consume(ctx, "rt-a"); err != nil {
		t.Fatalf("Consume after Inspect: %v", err)
	}
	// Delete is idempotent per RFC 7009 §2.2 and wipes the ledger.
	if err := s.Delete(ctx, "rt-b"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := s.Delete(ctx, "rt-b"); err != nil {
		t.Fatalf("Delete unknown (idempotent): %v", err)
	}
	_, err = s.Consume(ctx, "rt-b")
	assertSentinel(t, err, oauthspi.ErrRefreshTokenNotFound)
	_, err = s.Inspect(ctx, "rt-b")
	assertSentinel(t, err, oauthspi.ErrRefreshTokenNotFound)

	// CountForSubject dry-run.
	if n, err := s.CountForSubject(ctx, "u1", ""); err != nil || n != 1 {
		t.Fatalf("CountForSubject(u1, all) = (%d, %v), want 1", n, err)
	}
	if n, err := s.CountForSubject(ctx, "u1", "c1"); err != nil || n != 0 {
		t.Fatalf("CountForSubject(u1, c1) = (%d, %v), want 0", n, err)
	}
	// DeleteAllForSubject revokes across clients when clientID empty.
	if n, err := s.DeleteAllForSubject(ctx, "u1", ""); err != nil || n != 1 {
		t.Fatalf("DeleteAllForSubject(u1, all) = (%d, %v), want 1", n, err)
	}
	if n, err := s.DeleteAllForSubject(ctx, "", ""); err != nil || n != 0 {
		t.Fatalf("DeleteAllForSubject(empty user) = (%d, %v), want no-op", n, err)
	}
	// DeleteAllForClient purges by client; empty clientID MUST be a no-op.
	if n, err := s.DeleteAllForClient(ctx, "c1"); err != nil || n != 1 {
		t.Fatalf("DeleteAllForClient(c1) = (%d, %v), want 1", n, err)
	}
	if n, err := s.DeleteAllForClient(ctx, ""); err != nil || n != 0 {
		t.Fatalf("DeleteAllForClient(empty) = (%d, %v), want no-op", n, err)
	}
	// Ledger rows were wiped with the active rows: no reuse ghosts.
	_, err = s.Consume(ctx, "rt-c")
	assertSentinel(t, err, oauthspi.ErrRefreshTokenNotFound)
}

func TestRefreshTokenStore_ListExpiringThumbprintsStoredValue(t *testing.T) {
	db, dialect := freshOAuthStore(t)
	ctx := context.Background()
	s, err := NewRefreshTokenStoreWithDB(db, dialect)
	if err != nil {
		t.Fatalf("NewRefreshTokenStoreWithDB: %v", err)
	}
	now := time.Now()
	issue := func(token, family string, expiresAt time.Time) {
		t.Helper()
		if err := s.Issue(ctx, token, &oauthspi.RefreshToken{
			UserID: "u", ClientID: "c", IssuedAt: now,
			ExpiresAt: expiresAt, FamilyID: family,
		}); err != nil {
			t.Fatalf("Issue(%s): %v", token, err)
		}
	}
	issue("rt-e1", "f1", now.Add(24*time.Hour))
	issue("rt-e2", "f2", now.Add(48*time.Hour))
	issue("rt-past", "f3", now.Add(-time.Hour))

	// With HMAC keys configured, the thumbprint MUST be over the stored h1:
	// value (SQLite byte-parity), not the raw token — sha256(raw) would
	// differ and leak that the value is not stored raw.
	s.SetLookupHMACKeys([]byte("0123456789abcdef0123456789abcdef"))
	var stored string
	if err := db.QueryRowContext(ctx, `SELECT token FROM refresh_tokens WHERE token LIKE 'h1:%'`).Scan(&stored); err != nil {
		t.Fatalf("read stored token: %v", err)
	}
	list, err := s.ListExpiring(ctx, now.Add(36*time.Hour), 0)
	if err != nil {
		t.Fatalf("ListExpiring: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("ListExpiring len = %d, want 1 (expired row excluded, 48h row beyond before)", len(list))
	}
	if list[0].Thumbprint != oauthspi.RefreshTokenThumbprint(stored) {
		t.Fatalf("thumbprint = %q, want sha256 of stored h1: value %q", list[0].Thumbprint, stored)
	}
	if list[0].UserID != "u" || list[0].ClientID != "c" || !list[0].ExpiresAt.Equal(now.Add(24*time.Hour).UTC()) {
		t.Fatalf("expiry entry fields wrong: %+v", list[0])
	}
	// limit bounds the response.
	list, err = s.ListExpiring(ctx, now.Add(72*time.Hour), 1)
	if err != nil || len(list) != 1 || list[0].Thumbprint != oauthspi.RefreshTokenThumbprint(stored) {
		t.Fatalf("limited ListExpiring = (%+v, %v)", list, err)
	}
}

func TestRefreshTokenStore_RotationLimiter(t *testing.T) {
	db, dialect := freshOAuthStore(t)
	ctx := context.Background()
	s, err := NewRefreshTokenStoreWithDB(db, dialect)
	if err != nil {
		t.Fatalf("NewRefreshTokenStoreWithDB: %v", err)
	}
	// Empty family is a no-op.
	if n, exceeded, err := s.RecordRotation(ctx, ""); n != 0 || exceeded || err != nil {
		t.Fatalf("empty family = (%d, %v, %v)", n, exceeded, err)
	}
	// Unarmed cap: counts accumulate, never exceeded.
	for i := 1; i <= 3; i++ {
		n, exceeded, err := s.RecordRotation(ctx, "fam-cap")
		if err != nil || exceeded || n != i {
			t.Fatalf("RecordRotation #%d = (%d, %v, %v), want (%d, false, nil)", i, n, exceeded, err, i)
		}
	}
	// Armed cap: exceeded once count > MaxRotationsPerWindow.
	s.MaxRotationsPerWindow = 2
	s.RotationWindow = time.Hour
	if n, exceeded, err := s.RecordRotation(ctx, "fam-cap"); err != nil || !exceeded || n != 4 {
		t.Fatalf("capped RecordRotation = (%d, %v, %v), want (4, true, nil)", n, exceeded, err)
	}
	// Window rollover resets the count.
	s.RotationWindow = 0
	if err := db.QueryRowContext(ctx,
		`UPDATE refresh_rotation_windows SET window_start = $1 WHERE family_id = $2`,
		time.Now().Add(-2*time.Hour).UnixNano(), "fam-cap").Err(); err != nil {
		t.Fatalf("rewind window: %v", err)
	}
	s.RotationWindow = time.Hour
	if n, exceeded, err := s.RecordRotation(ctx, "fam-cap"); err != nil || exceeded || n != 1 {
		t.Fatalf("post-rollover = (%d, %v, %v), want (1, false, nil)", n, exceeded, err)
	}
	// DeleteFamily resets the window.
	if _, err := s.DeleteFamily(ctx, "fam-cap"); err != nil {
		t.Fatalf("DeleteFamily: %v", err)
	}
	if n, _, err := s.RecordRotation(ctx, "fam-cap"); err != nil || n != 1 {
		t.Fatalf("post-family-kill = (%d, %v), want 1", n, err)
	}
}

func TestRefreshTokenStore_ReaperPrunesLedgerAndRotationWindows(t *testing.T) {
	db, dialect := freshOAuthStore(t)
	ctx := context.Background()
	s, err := NewRefreshTokenStoreWithDB(db, dialect)
	if err != nil {
		t.Fatalf("NewRefreshTokenStoreWithDB: %v", err)
	}
	expired := time.Now().Add(-time.Minute)
	if err := s.Issue(ctx, "rt-old", &oauthspi.RefreshToken{
		UserID: "u", ClientID: "c", IssuedAt: time.Now(),
		ExpiresAt: expired, FamilyID: "fam-old",
	}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := s.Consume(ctx, "rt-old"); !errors.Is(err, oauthspi.ErrRefreshTokenReused) {
		t.Fatalf("consume expired = %v, want reuse signal (ledger row present)", err)
	}
	if _, _, err := s.RecordRotation(ctx, "fam-old"); err != nil {
		t.Fatalf("RecordRotation: %v", err)
	}
	s.StartReaper(0) // no-op guard: interval <= 0 must not panic
	now := time.Now()
	sweepStatements(t, db, now)
	var tokens, ledger, windows int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM refresh_tokens`).Scan(&tokens)
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM refresh_token_families`).Scan(&ledger)
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM refresh_rotation_windows`).Scan(&windows)
	if tokens != 0 || ledger != 0 || windows != 0 {
		t.Fatalf("post-sweep residue: tokens=%d ledger=%d windows=%d", tokens, ledger, windows)
	}
}

// sweepStatements replays the three reaper statements with a fixed timestamp
// so the test is deterministic (no goroutine timing).
func sweepStatements(t *testing.T, db *sql.DB, now time.Time) {
	t.Helper()
	nowNs := now.UnixNano()
	if _, err := db.ExecContext(context.Background(), `DELETE FROM refresh_token_families WHERE expires_at < $1`, nowNs); err != nil {
		t.Fatalf("sweep ledger: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), `DELETE FROM refresh_tokens WHERE expires_at < $1`, nowNs); err != nil {
		t.Fatalf("sweep tokens: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), `
        DELETE FROM refresh_rotation_windows
         WHERE family_id NOT IN (SELECT family_id FROM refresh_token_families)
           AND $1 > 0`, nowNs); err != nil {
		t.Fatalf("sweep windows: %v", err)
	}
}

func TestDeviceCodeStore_StateMachine(t *testing.T) {
	db, dialect := freshOAuthStore(t)
	ctx := context.Background()
	s, err := NewDeviceCodeStoreWithDB(db, dialect)
	if err != nil {
		t.Fatalf("NewDeviceCodeStoreWithDB: %v", err)
	}
	dc := &oauthspi.DeviceCode{
		DeviceCode: "dev-1", UserCode: "user-1", ClientID: "c1",
		Scopes: []string{"openid"}, Nonce: "n", Interval: 5 * time.Second,
		ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := s.Issue(ctx, dc); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Dual-key lookup + RAW re-stamp (stored values are opaque).
	byDevice, err := s.GetByDeviceCode(ctx, "dev-1")
	if err != nil || byDevice.DeviceCode != "dev-1" || byDevice.Interval != 5*time.Second {
		t.Fatalf("GetByDeviceCode = (%+v, %v)", byDevice, err)
	}
	byUser, err := s.GetByUserCode(ctx, "user-1")
	if err != nil || byUser.UserCode != "user-1" || byUser.ClientID != "c1" {
		t.Fatalf("GetByUserCode = (%+v, %v)", byUser, err)
	}
	// Pending code cannot be consumed.
	_, err = s.ConsumeIfApproved(ctx, "dev-1")
	assertSentinel(t, err, oauthspi.ErrDeviceCodeNotFound)
	// Approve + deny state machine.
	if err := s.Approve(ctx, "user-1", "u9", "pwd", map[string]string{"k": "v"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	approved, err := s.GetByDeviceCode(ctx, "dev-1")
	if err != nil || !approved.Approved || approved.UserID != "u9" || approved.Provider != "pwd" || approved.Attributes["k"] != "v" {
		t.Fatalf("approved record wrong: %+v err=%v", approved, err)
	}
	if err := s.UpdateLastPoll(ctx, "dev-1", time.Now()); err != nil {
		t.Fatalf("UpdateLastPoll: %v", err)
	}
	// ConsumeIfApproved wins exactly once.
	out, err := s.ConsumeIfApproved(ctx, "dev-1")
	if err != nil || out.DeviceCode != "dev-1" || out.UserID != "u9" {
		t.Fatalf("ConsumeIfApproved = (%+v, %v)", out, err)
	}
	_, err = s.ConsumeIfApproved(ctx, "dev-1")
	assertSentinel(t, err, oauthspi.ErrDeviceCodeNotFound)
	// Deny path.
	dc2 := &oauthspi.DeviceCode{DeviceCode: "dev-2", UserCode: "user-2", ClientID: "c1", ExpiresAt: time.Now().Add(time.Minute)}
	if err := s.Issue(ctx, dc2); err != nil {
		t.Fatalf("Issue dev-2: %v", err)
	}
	if err := s.Deny(ctx, "user-2"); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	denied, err := s.GetByUserCode(ctx, "user-2")
	if err != nil || !denied.Denied {
		t.Fatalf("denied record wrong: %+v err=%v", denied, err)
	}
	_, err = s.ConsumeIfApproved(ctx, "dev-2")
	assertSentinel(t, err, oauthspi.ErrDeviceCodeNotFound)
	// Delete is idempotent.
	if err := s.Delete(ctx, "dev-2"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := s.Delete(ctx, "dev-2"); err != nil {
		t.Fatalf("Delete idempotent: %v", err)
	}
}

func TestDeviceCodeStore_ConcurrentConsumeSingleWinner(t *testing.T) {
	db, dialect := freshOAuthStore(t)
	ctx := context.Background()
	s, err := NewDeviceCodeStoreWithDB(db, dialect)
	if err != nil {
		t.Fatalf("NewDeviceCodeStoreWithDB: %v", err)
	}
	if err := s.Issue(ctx, &oauthspi.DeviceCode{
		DeviceCode: "dev-race", UserCode: "user-race", ClientID: "c1",
		ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.Approve(ctx, "user-race", "u9", "pwd", nil); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	var (
		wg      sync.WaitGroup
		winners atomicInt
	)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := s.ConsumeIfApproved(ctx, "dev-race")
			if err == nil && out != nil {
				winners.add(1)
			} else {
				assertSentinel(t, err, oauthspi.ErrDeviceCodeNotFound)
			}
		}()
	}
	wg.Wait()
	if winners.load() != 1 {
		t.Fatalf("winners = %d, want exactly 1", winners.load())
	}
}

func TestDeviceCodeStore_UserCodeUnique(t *testing.T) {
	db, dialect := freshOAuthStore(t)
	ctx := context.Background()
	s, err := NewDeviceCodeStoreWithDB(db, dialect)
	if err != nil {
		t.Fatalf("NewDeviceCodeStoreWithDB: %v", err)
	}
	if err := s.Issue(ctx, &oauthspi.DeviceCode{
		DeviceCode: "dev-a", UserCode: "same-code", ClientID: "c1", ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// A colliding user_code must fail loudly (UNIQUE constraint), never
	// silently overwrite the first code.
	if err := s.Issue(ctx, &oauthspi.DeviceCode{
		DeviceCode: "dev-b", UserCode: "same-code", ClientID: "c2", ExpiresAt: time.Now().Add(time.Minute),
	}); err == nil {
		t.Fatal("duplicate user_code accepted — UNIQUE constraint missing")
	}
}

func TestPARStore_RoundTripSingleUseAndExpiry(t *testing.T) {
	db, dialect := freshOAuthStore(t)
	ctx := context.Background()
	s, err := NewPARStoreWithDB(db, dialect)
	if err != nil {
		t.Fatalf("NewPARStoreWithDB: %v", err)
	}
	req := &oauthspi.PARRequest{
		ClientID: "c1", ResponseType: "code", RedirectURI: "https://rp/cb",
		Scope: []string{"openid"}, State: "st", Nonce: "n",
		CodeChallenge: "chal", CodeChallengeMethod: "S256",
		Resource:             []string{"https://api.example"},
		AuthorizationDetails: json.RawMessage(`[{"type":"payment"}]`),
		LoginHint:            "alice", ResponseMode: "form_post",
		ACRValues: "acr1", UILocales: "en-US",
		Claims:    json.RawMessage(`{"id_token":{}}`),
		ExpiresAt: time.Now().Add(90 * time.Second),
	}
	uri, err := s.Issue(ctx, req)
	if err != nil || uri == "" || uri[:len(oauthspi.PARURIPrefix)] != oauthspi.PARURIPrefix {
		t.Fatalf("Issue = (%q, %v)", uri, err)
	}
	out, err := s.Consume(ctx, uri)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if out.ClientID != "c1" || out.ResponseType != "code" || len(out.Scope) != 1 ||
		out.CodeChallenge != "chal" || len(out.Resource) != 1 ||
		string(out.AuthorizationDetails) != `[{"type":"payment"}]` ||
		out.LoginHint != "alice" || out.ResponseMode != "form_post" ||
		out.ACRValues != "acr1" || out.UILocales != "en-US" ||
		string(out.Claims) != `{"id_token":{}}` {
		t.Fatalf("PAR round-trip lost fields: %+v", out)
	}
	_, err = s.Consume(ctx, uri)
	assertSentinel(t, err, oauthspi.ErrPARNotFound)
	// Expired request collapses to the same sentinel.
	uri2, err := s.Issue(ctx, &oauthspi.PARRequest{
		ClientID: "c1", ExpiresAt: time.Now().Add(-time.Second),
	})
	if err != nil {
		t.Fatalf("Issue expired: %v", err)
	}
	_, err = s.Consume(ctx, uri2)
	assertSentinel(t, err, oauthspi.ErrPARNotFound)
}

func TestPARStore_ConcurrentConsumeSingleWinner(t *testing.T) {
	db, dialect := freshOAuthStore(t)
	ctx := context.Background()
	s, err := NewPARStoreWithDB(db, dialect)
	if err != nil {
		t.Fatalf("NewPARStoreWithDB: %v", err)
	}
	uri, err := s.Issue(ctx, &oauthspi.PARRequest{
		ClientID: "c1", ExpiresAt: time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	var (
		wg      sync.WaitGroup
		winners atomicInt
	)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := s.Consume(ctx, uri)
			if err == nil && out != nil {
				winners.add(1)
			} else {
				assertSentinel(t, err, oauthspi.ErrPARNotFound)
			}
		}()
	}
	wg.Wait()
	if winners.load() != 1 {
		t.Fatalf("winners = %d, want exactly 1", winners.load())
	}
}

func TestRefreshGraceStore_RememberLookupAndFailClosed(t *testing.T) {
	db, dialect := freshOAuthStore(t)
	ctx := context.Background()
	s, err := NewRefreshGraceStoreWithDB(db, dialect, 10*time.Minute, 0)
	if err != nil {
		t.Fatalf("NewRefreshGraceStoreWithDB: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	now := time.Now()
	resp := map[string]any{"access_token": "at-1", "refresh_token": "rt-1"}
	// Remember is idempotent; Lookup replays the same successor.
	s.Remember("consumed-token", resp, now)
	got, ok := s.Lookup("consumed-token", now.Add(time.Second))
	if !ok || got["access_token"] != "at-1" || got["refresh_token"] != "rt-1" {
		t.Fatalf("Lookup = (%v, %v)", got, ok)
	}
	// Only the hash is stored — never the secret.
	var stored string
	if err := db.QueryRowContext(ctx, `SELECT consumed_token_hash FROM refresh_grace_cache`).Scan(&stored); err != nil {
		t.Fatalf("read hash: %v", err)
	}
	if stored == "consumed-token" || stored != refreshGraceHash("consumed-token") {
		t.Fatalf("stored key %q is not the one-way hash", stored)
	}
	// Expired-at-now is treated as expired: fail closed to reuse detection.
	if _, ok := s.Lookup("consumed-token", now.Add(10*time.Minute)); ok {
		t.Fatal("Lookup after window must be a miss")
	}
	// Miss and empty token are fail-closed misses.
	if _, ok := s.Lookup("never-remembered", now); ok {
		t.Fatal("Lookup of unknown token must be a miss")
	}
	if _, ok := s.Lookup("", now); ok {
		t.Fatal("Lookup of empty token must be a miss")
	}
	// PruneExpired removes expired rows.
	if n, err := s.PruneExpired(ctx); err != nil || n != 1 {
		t.Fatalf("PruneExpired = (%d, %v), want (1, nil)", n, err)
	}
	if _, ok := s.Lookup("consumed-token", now.Add(time.Second)); ok {
		t.Fatal("Lookup after prune must be a miss")
	}
}

// TestOAuthStores_OptionalSurfaceGuard is the Decision-2 guard: the postgres
// refresh store implements the FULL optional assertion set the SQLite peer
// carries, in one place, so a future edit that drops an interface fails the
// build/test loudly instead of silently degrading a shipped feature.
func TestOAuthStores_OptionalSurfaceGuard(t *testing.T) {
	db, dialect := freshOAuthStore(t)
	s, err := NewRefreshTokenStoreWithDB(db, dialect)
	if err != nil {
		t.Fatalf("NewRefreshTokenStoreWithDB: %v", err)
	}
	var store any = s
	assertions := []struct {
		name string
		ok   bool
	}{
		{"RefreshTokenStore", func() bool { _, ok := store.(oauthspi.RefreshTokenStore); return ok }()},
		{"RefreshTokenInspector", func() bool { _, ok := store.(oauthspi.RefreshTokenInspector); return ok }()},
		{"RefreshTokenSubjectIndex", func() bool { _, ok := store.(oauthspi.RefreshTokenSubjectIndex); return ok }()},
		{"RefreshTokenSubjectCounter", func() bool { _, ok := store.(oauthspi.RefreshTokenSubjectCounter); return ok }()},
		{"RefreshTokenClientPurger", func() bool { _, ok := store.(oauthspi.RefreshTokenClientPurger); return ok }()},
		{"RefreshTokenFamilyTracker", func() bool { _, ok := store.(oauthspi.RefreshTokenFamilyTracker); return ok }()},
		{"RefreshTokenRotationLimiter", func() bool { _, ok := store.(oauthspi.RefreshTokenRotationLimiter); return ok }()},
		{"RefreshTokenExpiryLister", func() bool { _, ok := store.(oauthspi.RefreshTokenExpiryLister); return ok }()},
	}
	for _, a := range assertions {
		if !a.ok {
			t.Errorf("postgres RefreshTokenStore dropped optional interface %s", a.name)
		}
	}
	// SetLookupHMACKeys is on every store.
	for _, st := range []any{s} {
		if _, ok := st.(interface{ SetLookupHMACKeys(...[]byte) }); !ok {
			t.Errorf("%T dropped SetLookupHMACKeys", st)
		}
	}
}

// atomicInt is a tiny race-safe counter for the concurrency tests.
type atomicInt struct {
	mu sync.Mutex
	n  int
}

func (a *atomicInt) add(n int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.n += n
}

func (a *atomicInt) load() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.n
}
