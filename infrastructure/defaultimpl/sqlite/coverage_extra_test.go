package sqlite_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"

	"golang.org/x/crypto/bcrypt"

	_ "modernc.org/sqlite"
)

// TestDBErrorsAreWrappedNotPanicked drops a store's backing table out from
// under it and asserts each read/list method returns a wrapped error rather
// than panicking. This exercises the `if err != nil { return fmt.Errorf }`
// branches that the happy-path tests never reach, and pins the contract that
// a corrupt/migrating schema degrades to an error the caller can log.
func TestDBErrorsAreWrappedNotPanicked(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Open-DSN constructors migrate the schema, so the table exists to drop.
	clients, err := sqlite.NewClientStore("file:" + filepath.Join(t.TempDir(), "cl.db"))
	if err != nil {
		t.Fatalf("clients: %v", err)
	}
	t.Cleanup(func() { _ = clients.Close() })
	users, err := sqlite.NewUserProvider("file:" + filepath.Join(t.TempDir(), "us.db"))
	if err != nil {
		t.Fatalf("users: %v", err)
	}
	t.Cleanup(func() { _ = users.Close() })
	rt, err := sqlite.NewRefreshTokenStore("file:" + filepath.Join(t.TempDir(), "rt.db"))
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	if _, err := clients.DB().ExecContext(ctx, "DROP TABLE clients"); err != nil {
		t.Fatalf("drop clients: %v", err)
	}
	if _, err := users.DB().ExecContext(ctx, "DROP TABLE users"); err != nil {
		t.Fatalf("drop users: %v", err)
	}
	if _, err := rt.DB().ExecContext(ctx, "DROP TABLE refresh_tokens"); err != nil {
		t.Fatalf("drop refresh_tokens: %v", err)
	}

	// ClientStore read paths.
	if _, err := clients.List(ctx); err == nil {
		t.Error("clients.List: want error after table drop")
	}
	if _, err := clients.ListByTenant(ctx, "t"); err == nil {
		t.Error("clients.ListByTenant: want error")
	}
	if _, _, err := clients.Stats(ctx); err == nil {
		t.Error("clients.Stats: want error")
	}
	if _, err := clients.Get(ctx, "x"); err == nil {
		t.Error("clients.Get: want error")
	}

	// UserProvider read paths.
	if _, err := users.List(ctx); err == nil {
		t.Error("users.List: want error")
	}
	if _, err := users.GetByID(ctx, "x"); err == nil {
		t.Error("users.GetByID: want error")
	}

	// ClientStore mutation paths also wrap the underlying error.
	if err := clients.Update(ctx, &sso.Client{ID: "x"}); err == nil {
		t.Error("clients.Update: want error")
	}
	if err := clients.Put(ctx, &sso.Client{ID: "x"}); err == nil {
		t.Error("clients.Put: want error")
	}

	// RefreshTokenStore read/count/mutation paths.
	if _, err := rt.CountForSubject(ctx, "u", "c"); err == nil {
		t.Error("rt.CountForSubject: want error")
	}
	if _, err := rt.Inspect(ctx, "tok"); err == nil {
		t.Error("rt.Inspect: want error")
	}
	if err := rt.Issue(ctx, "tok", &oauth.RefreshToken{
		UserID: "u", ClientID: "c", ExpiresAt: time.Now().Add(time.Hour),
	}); err == nil {
		t.Error("rt.Issue: want error")
	}
	if err := rt.Delete(ctx, "tok"); err == nil {
		t.Error("rt.Delete: want error")
	}
	if _, err := rt.DeleteFamily(ctx, "fam"); err == nil {
		t.Error("rt.DeleteFamily: want error")
	}
}

// TestInputGuards_RejectEmptyArgs hits the cheap fast-fail guards that the
// happy-path tests skip: empty primary keys / nil payloads collapse to the
// store's typed sentinel or a no-op, never an INSERT.
func TestInputGuards_RejectEmptyArgs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// AuthCode.Issue: empty code OR nil info → ErrAuthCodeNotFound.
	ac, err := sqlite.NewAuthCodeStore("file:" + filepath.Join(t.TempDir(), "ac.db"))
	if err != nil {
		t.Fatalf("authcode: %v", err)
	}
	t.Cleanup(func() { _ = ac.Close() })
	if err := ac.Issue(ctx, "", &oauth.AuthCode{}); !errors.Is(err, oauth.ErrAuthCodeNotFound) {
		t.Errorf("AuthCode.Issue(empty code): %v", err)
	}
	if err := ac.Issue(ctx, "x", nil); !errors.Is(err, oauth.ErrAuthCodeNotFound) {
		t.Errorf("AuthCode.Issue(nil info): %v", err)
	}

	// RefreshToken.Issue: empty token OR nil info → ErrRefreshTokenNotFound;
	// DeleteFamily/DeleteAllForClient empty arg → (0,nil) no-op.
	rt := sqlite.NewRefreshTokenStoreWithDB(newSharedDB(t))
	if err := rt.Issue(ctx, "", &oauth.RefreshToken{}); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("Refresh.Issue(empty): %v", err)
	}
	if err := rt.Issue(ctx, "t", nil); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("Refresh.Issue(nil): %v", err)
	}
	if n, _ := rt.DeleteFamily(ctx, ""); n != 0 {
		t.Errorf("DeleteFamily(empty) = %d, want 0", n)
	}
	if n, _ := rt.CountForSubject(ctx, "", ""); n != 0 {
		t.Errorf("CountForSubject(empty) = %d, want 0", n)
	}
	if _, err := rt.Inspect(ctx, "ghost"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("Inspect(unknown): %v", err)
	}
	// Delete is idempotent on an unknown token (RFC 7009 §2.2).
	if err := rt.Delete(ctx, "ghost"); err != nil {
		t.Errorf("Delete(unknown): %v", err)
	}

	// CIBA.SetStatus: empty id → ErrCIBARequestNotFound (no Get round-trip).
	ciba, err := sqlite.NewCIBAStore("file:" + filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatalf("ciba: %v", err)
	}
	t.Cleanup(func() { _ = ciba.Close() })
	if err := ciba.SetStatus(ctx, "", oauth.CIBAApproved); !errors.Is(err, oauth.ErrCIBARequestNotFound) {
		t.Errorf("CIBA.SetStatus(empty): %v", err)
	}
}

// TestRefreshTokenStore_InspectGCsExpired proves the non-destructive Inspect
// path opportunistically deletes an entry it finds expired, so a later
// presentation looks like a vanilla unknown token rather than a stale row.
func TestRefreshTokenStore_InspectGCsExpired(t *testing.T) {
	t.Parallel()
	rt := sqlite.NewRefreshTokenStoreWithDB(newSharedDB(t))
	ctx := context.Background()
	if err := rt.Issue(ctx, "exptok", &oauth.RefreshToken{
		UserID: "u", ClientID: "c", FamilyID: "fam",
		ExpiresAt: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := rt.Inspect(ctx, "exptok"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("Inspect(expired): %v", err)
	}
	// The opportunistic GC removed the row.
	var n int
	if err := rt.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM refresh_tokens WHERE token='exptok'`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("expired row not GC'd by Inspect: count=%d", n)
	}
}

// TestDeviceCodeStore_UpdateLastPollAndDeleteEdges covers the not-found and
// idempotent-delete branches the happy-path state-machine test does not.
func TestDeviceCodeStore_UpdateLastPollAndDeleteEdges(t *testing.T) {
	t.Parallel()
	st, err := sqlite.NewDeviceCodeStore("file:" + filepath.Join(t.TempDir(), "dc.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()

	// UpdateLastPoll on an unknown device code → ErrDeviceCodeNotFound.
	if err := st.UpdateLastPoll(ctx, "ghost", time.Now()); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Errorf("UpdateLastPoll(unknown): %v", err)
	}
	// Delete is idempotent on a missing code.
	if err := st.Delete(ctx, "ghost"); err != nil {
		t.Errorf("Delete(unknown): %v", err)
	}

	// An expired entry surfaces as not-found AND is opportunistically GC'd on
	// fetch (fetch IsExpired branch).
	_ = st.Issue(ctx, &oauth.DeviceCode{
		DeviceCode: "EXP", UserCode: "EU", ClientID: "c",
		ExpiresAt: time.Now().Add(-time.Minute),
	})
	if _, err := st.GetByDeviceCode(ctx, "EXP"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Errorf("GetByDeviceCode(expired): %v", err)
	}
}

// TestClientStore_Put_UpsertAndRehash exercises the admin/bootstrap Put
// (INSERT OR REPLACE) path: a fresh insert hashes the plaintext secret, a
// re-Put with an already-bcrypt secret is stored verbatim (no double-hash),
// and an empty ID is rejected.
func TestClientStore_Put_UpsertAndRehash(t *testing.T) {
	t.Parallel()
	st := newClientStore(t)
	ctx := context.Background()

	// Active: ValidateSecret rejects inactive clients (parity with memory),
	// and this test asserts the secret-validation path, not the active gate.
	if err := st.Put(ctx, &sso.Client{ID: "p1", Secret: "plain", Name: "First", Active: true}); err != nil {
		t.Fatalf("Put (insert): %v", err)
	}
	got, err := st.Get(ctx, "p1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if err := st.ValidateSecret(ctx, "p1", "plain"); err != nil {
		t.Errorf("ValidateSecret after Put: %v", err)
	}
	hashed := got.Secret // already a bcrypt hash

	// Re-Put with the bcrypt value: must NOT re-hash (validates against the
	// same plaintext still), and Name update takes effect (overwrite).
	if err := st.Put(ctx, &sso.Client{ID: "p1", Secret: hashed, Name: "Second", Active: true}); err != nil {
		t.Fatalf("Put (upsert): %v", err)
	}
	got2, err := st.Get(ctx, "p1")
	if err != nil {
		t.Fatalf("Get after upsert: %v", err)
	}
	if got2.Name != "Second" {
		t.Errorf("upsert did not overwrite Name: %q", got2.Name)
	}
	if got2.Secret != hashed {
		t.Errorf("bcrypt secret got re-hashed on Put")
	}
	if err := st.ValidateSecret(ctx, "p1", "plain"); err != nil {
		t.Errorf("ValidateSecret after upsert: %v", err)
	}

	if err := st.Put(ctx, &sso.Client{ID: ""}); err == nil {
		t.Errorf("Put with empty ID: want error, got nil")
	}
	if err := st.Put(ctx, nil); err == nil {
		t.Errorf("Put(nil): want error, got nil")
	}
}

// TestCIBAStore_Delete proves Delete removes the request (Get then collapses
// to the not-found sentinel) and is idempotent on a missing/empty id.
func TestCIBAStore_Delete(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "ciba.db") + "?_pragma=busy_timeout(5000)"
	s, err := sqlite.NewCIBAStore(dsn)
	if err != nil {
		t.Fatalf("NewCIBAStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	now := time.Now().UTC()
	id, err := s.Issue(ctx, &oauth.CIBARequest{
		ClientID: "c", SubjectID: "u", Provider: "ciba",
		CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.Delete(ctx, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, id); !errors.Is(err, oauth.ErrCIBARequestNotFound) {
		t.Errorf("Get after Delete: got %v, want ErrCIBARequestNotFound", err)
	}
	// Idempotent.
	if err := s.Delete(ctx, id); err != nil {
		t.Errorf("Delete (missing): %v", err)
	}
	if err := s.Delete(ctx, ""); err != nil {
		t.Errorf("Delete (empty): %v", err)
	}
}

// TestPasswordStore_SetPasswordHash covers the PasswordHashImporter path:
// a valid bcrypt hash is seeded verbatim (VerifyPassword then matches the
// original plaintext), a non-bcrypt value is rejected (never stored as a
// fake hash), and an empty userID collapses to the mismatch sentinel.
func TestPasswordStore_SetPasswordHash(t *testing.T) {
	t.Parallel()
	ps := newTestPasswordStore(t)
	ctx := context.Background()

	h, err := bcrypt.GenerateFromPassword([]byte("imported-secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	if err := ps.SetPasswordHash(ctx, "imp", string(h)); err != nil {
		t.Fatalf("SetPasswordHash: %v", err)
	}
	if err := ps.VerifyPassword(ctx, "imp", "imported-secret"); err != nil {
		t.Errorf("VerifyPassword after import: %v", err)
	}

	if err := ps.SetPasswordHash(ctx, "imp", "not-a-bcrypt-hash"); err == nil {
		t.Errorf("SetPasswordHash with plaintext: want error, got nil")
	}
	if err := ps.SetPasswordHash(ctx, "", string(h)); !errors.Is(err, core.ErrPasswordMismatch) {
		t.Errorf("SetPasswordHash empty userID: got %v, want ErrPasswordMismatch", err)
	}
}

// TestIPFailureCounter_RecordCountPruneOlder drives the anomaly counter end
// to end: record two failures, count them, then PruneOlder past their
// timestamp removes them. Empty-ip and zero-cutoff guards are also covered.
func TestIPFailureCounter_RecordCountPruneOlder(t *testing.T) {
	t.Parallel()
	c, err := sqlite.NewIPFailureCounter("file:" + filepath.Join(t.TempDir(), "ipf.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	ctx := context.Background()

	base := time.Now()
	_ = c.Record(ctx, "", "iphash", "alice", base.Add(-2*time.Minute))
	_ = c.Record(ctx, "", "iphash", "bob", base.Add(-time.Minute))
	if err := c.Record(ctx, "", "", "x", base); err != nil { // empty ip = no-op
		t.Errorf("Record empty ip: %v", err)
	}

	total, distinct, err := c.Count(ctx, "", "iphash", base.Add(-time.Hour))
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if total != 2 || distinct != 2 {
		t.Errorf("Count = (%d,%d), want (2,2)", total, distinct)
	}

	// Zero cutoff is a no-op guard.
	if n, _ := c.PruneOlder(ctx, time.Time{}); n != 0 {
		t.Errorf("PruneOlder(zero) removed %d, want 0", n)
	}
	n, err := c.PruneOlder(ctx, base)
	if err != nil {
		t.Fatalf("PruneOlder: %v", err)
	}
	if n != 2 {
		t.Errorf("PruneOlder removed %d, want 2", n)
	}
	total, _, _ = c.Count(ctx, "", "iphash", time.Time{})
	if total != 0 {
		t.Errorf("post-prune total = %d, want 0", total)
	}
}

// TestRefreshTokenStore_RecordRotation_VelocityCap arms the optional
// per-family rotation limiter and proves: empty family is a no-op, the count
// climbs per call, and crossing MaxRotationsPerWindow flips exceeded.
func TestRefreshTokenStore_RecordRotation_VelocityCap(t *testing.T) {
	t.Parallel()
	s := sqlite.NewRefreshTokenStoreWithDB(newSharedDB(t))
	s.MaxRotationsPerWindow = 2
	s.RotationWindow = time.Hour
	ctx := context.Background()

	if n, exceeded, err := s.RecordRotation(ctx, ""); err != nil || n != 0 || exceeded {
		t.Errorf("empty family: (%d,%v,%v), want (0,false,nil)", n, exceeded, err)
	}

	n1, e1, err := s.RecordRotation(ctx, "fam")
	if err != nil || n1 != 1 || e1 {
		t.Fatalf("rotation 1: (%d,%v,%v), want (1,false,nil)", n1, e1, err)
	}
	n2, e2, _ := s.RecordRotation(ctx, "fam")
	if n2 != 2 || e2 {
		t.Fatalf("rotation 2: (%d,%v), want (2,false)", n2, e2)
	}
	n3, e3, _ := s.RecordRotation(ctx, "fam")
	if n3 != 3 || !e3 {
		t.Errorf("rotation 3: (%d,%v), want (3,true) — over cap", n3, e3)
	}

	// A different family has its own independent window.
	if n, exceeded, _ := s.RecordRotation(ctx, "other"); n != 1 || exceeded {
		t.Errorf("other family: (%d,%v), want (1,false)", n, exceeded)
	}
}

// TestRefreshTokenStore_RecordRotation_WindowRollover proves the fixed-window
// counter resets once the configured window elapses: a sub-millisecond window
// means the second rotation starts a fresh window at count 1 rather than
// accumulating.
func TestRefreshTokenStore_RecordRotation_WindowRollover(t *testing.T) {
	t.Parallel()
	s := sqlite.NewRefreshTokenStoreWithDB(newSharedDB(t))
	s.MaxRotationsPerWindow = 5
	s.RotationWindow = time.Millisecond
	ctx := context.Background()

	if n, _, err := s.RecordRotation(ctx, "fam"); err != nil || n != 1 {
		t.Fatalf("rotation 1: n=%d err=%v", n, err)
	}
	time.Sleep(3 * time.Millisecond) // let the window elapse
	n, exceeded, err := s.RecordRotation(ctx, "fam")
	if err != nil {
		t.Fatalf("rotation 2: %v", err)
	}
	if n != 1 || exceeded {
		t.Errorf("post-rollover: (%d,%v), want (1,false) — window did not reset", n, exceeded)
	}
}

// TestClientStore_Put_HashesRegistrationAccessToken proves the RFC 7592
// management credential is bcrypt-hashed at rest by Put (same as the secret),
// covering the RAT re-hash branch.
func TestClientStore_Put_HashesRegistrationAccessToken(t *testing.T) {
	t.Parallel()
	st := newClientStore(t)
	ctx := context.Background()
	if err := st.Put(ctx, &sso.Client{
		ID: "rat", Secret: "s", RegistrationAccessToken: "plain-rat",
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := st.Get(ctx, "rat")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.RegistrationAccessToken == "plain-rat" || got.RegistrationAccessToken == "" {
		t.Errorf("RAT not hashed at rest: %q", got.RegistrationAccessToken)
	}
}

// TestDeviceSecretStore_RevokeBySubject proves an admin device-lockout drops
// every binding for the subject (and only that subject) and returns the
// count.
func TestDeviceSecretStore_RevokeBySubject(t *testing.T) {
	t.Parallel()
	s, err := sqlite.NewDeviceSecretStore("file:" + filepath.Join(t.TempDir(), "ds.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	exp := time.Now().Add(time.Hour)
	_ = s.Issue(ctx, &core.DeviceSecret{Secret: "a", Subject: "victim", ClientID: "c", ExpiresAt: exp})
	_ = s.Issue(ctx, &core.DeviceSecret{Secret: "b", Subject: "victim", ClientID: "c", ExpiresAt: exp})
	_ = s.Issue(ctx, &core.DeviceSecret{Secret: "c", Subject: "bystander", ClientID: "c", ExpiresAt: exp})

	n, err := s.RevokeBySubject(ctx, "victim")
	if err != nil {
		t.Fatalf("RevokeBySubject: %v", err)
	}
	if n != 2 {
		t.Errorf("revoked %d, want 2", n)
	}
	// Victim's secrets are gone; bystander survives.
	if _, err := s.Consume(ctx, "a"); !errors.Is(err, core.ErrDeviceSecretNotFound) {
		t.Errorf("victim secret a survived: %v", err)
	}
	if _, err := s.Consume(ctx, "c"); err != nil {
		t.Errorf("bystander secret revoked: %v", err)
	}
	// Idempotent on an unknown subject.
	if n, _ := s.RevokeBySubject(ctx, "nobody"); n != 0 {
		t.Errorf("RevokeBySubject(unknown) = %d, want 0", n)
	}
}
