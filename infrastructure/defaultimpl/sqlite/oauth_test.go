package sqlite_test

import "github.com/snaplink/sso/protocols/oauth"

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
)

// freshSharedDSN returns a per-test in-memory DB shared across all
// connections in this process. cache=shared lets the connection pool
// keep open across goroutines without losing the table.
func freshSharedDSN(t *testing.T) string {
	t.Helper()
	// Unique name per-test so parallel tests don't share schema state.
	return "file:" + t.Name() + ".db?mode=memory&cache=shared&_pragma=busy_timeout(5000)"
}

// ---------- oauth.AuthCodeStore ----------

func TestSQLiteAuthCode_RoundTrip(t *testing.T) {
	t.Parallel()
	st, err := sqlite.NewAuthCodeStore(freshSharedDSN(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	in := &oauth.AuthCode{
		UserID:              "u-1",
		ClientID:            "web",
		RedirectURI:         "https://app/cb",
		Scopes:              []string{"openid", "profile"},
		Nonce:               "n1",
		Provider:            "password",
		Attributes:          map[string]string{"role": "admin"},
		CodeChallenge:       "challenge-xyz",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(time.Minute),
	}
	if err := st.Issue(context.Background(), "code-1", in); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	out, err := st.Consume(context.Background(), "code-1")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if out.UserID != "u-1" || out.ClientID != "web" || out.RedirectURI != "https://app/cb" {
		t.Errorf("payload mismatch: %+v", out)
	}
	if len(out.Scopes) != 2 || out.Attributes["role"] != "admin" {
		t.Errorf("slice/map lost: %+v", out)
	}
	if out.CodeChallenge != "challenge-xyz" || out.CodeChallengeMethod != "S256" {
		t.Errorf("PKCE fields lost: %+v", out)
	}
}

func TestSQLiteAuthCode_SingleUse(t *testing.T) {
	t.Parallel()
	st, err := sqlite.NewAuthCodeStore(freshSharedDSN(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	_ = st.Issue(context.Background(), "c", &oauth.AuthCode{
		UserID: "u", ClientID: "c", ExpiresAt: time.Now().Add(time.Minute),
	})
	if _, err := st.Consume(context.Background(), "c"); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if _, err := st.Consume(context.Background(), "c"); !errors.Is(err, oauth.ErrAuthCodeNotFound) {
		t.Errorf("second Consume err = %v want oauth.ErrAuthCodeNotFound", err)
	}
}

func TestSQLiteAuthCode_ExpiredIndistinguishable(t *testing.T) {
	t.Parallel()
	st, err := sqlite.NewAuthCodeStore(freshSharedDSN(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	_ = st.Issue(context.Background(), "stale", &oauth.AuthCode{
		UserID: "u", ClientID: "c", ExpiresAt: time.Now().Add(-time.Hour),
	})
	if _, err := st.Consume(context.Background(), "stale"); !errors.Is(err, oauth.ErrAuthCodeNotFound) {
		t.Errorf("err = %v want oauth.ErrAuthCodeNotFound", err)
	}
}

func TestSQLiteAuthCode_UnknownReturnsSentinel(t *testing.T) {
	t.Parallel()
	st, err := sqlite.NewAuthCodeStore(freshSharedDSN(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if _, err := st.Consume(context.Background(), "ghost"); !errors.Is(err, oauth.ErrAuthCodeNotFound) {
		t.Errorf("err = %v want oauth.ErrAuthCodeNotFound", err)
	}
}

// ---------- oauth.RefreshTokenStore ----------

func TestSQLiteRefresh_RoundTripAndRotation(t *testing.T) {
	t.Parallel()
	st, err := sqlite.NewRefreshTokenStore(freshSharedDSN(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now()
	in := &oauth.RefreshToken{
		UserID: "u-1", ClientID: "web", Provider: "password",
		Scopes:     []string{"openid", "profile"},
		Attributes: map[string]string{"role": "admin"},
		IssuedAt:   now, ExpiresAt: now.Add(time.Hour),
	}
	if err := st.Issue(context.Background(), "tok", in); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	out, err := st.Consume(context.Background(), "tok")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if out.UserID != "u-1" || out.Provider != "password" {
		t.Errorf("payload mismatch: %+v", out)
	}
	// Rotation: second Consume must fail.
	if _, err := st.Consume(context.Background(), "tok"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("replay err = %v want oauth.ErrRefreshTokenNotFound", err)
	}
}

func TestSQLiteRefresh_CountForSubject(t *testing.T) {
	t.Parallel()
	st, err := sqlite.NewRefreshTokenStore(freshSharedDSN(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	ctx := context.Background()
	exp := time.Now().Add(time.Hour)
	_ = st.Issue(ctx, "t1", &oauth.RefreshToken{UserID: "u", ClientID: "c1", ExpiresAt: exp})
	_ = st.Issue(ctx, "t2", &oauth.RefreshToken{UserID: "u", ClientID: "c1", ExpiresAt: exp})
	_ = st.Issue(ctx, "t3", &oauth.RefreshToken{UserID: "u", ClientID: "c2", ExpiresAt: exp})
	_ = st.Issue(ctx, "t4", &oauth.RefreshToken{UserID: "other", ClientID: "c1", ExpiresAt: exp})

	if n, _ := st.CountForSubject(ctx, "u", "c1"); n != 2 {
		t.Errorf("count(u,c1) = %d, want 2", n)
	}
	if n, _ := st.CountForSubject(ctx, "u", ""); n != 3 {
		t.Errorf("count(u, all) = %d, want 3", n)
	}
	// Non-destructive: a delete still finds the tokens afterwards.
	if n, _ := st.DeleteAllForSubject(ctx, "u", "c1"); n != 2 {
		t.Errorf("delete(u,c1) = %d, want 2 (count must not have removed them)", n)
	}
}

func TestSQLiteRefresh_InspectAndDelete(t *testing.T) {
	t.Parallel()
	st, err := sqlite.NewRefreshTokenStore(freshSharedDSN(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	_ = st.Issue(context.Background(), "tok", &oauth.RefreshToken{
		UserID: "u", ClientID: "c", ExpiresAt: time.Now().Add(time.Hour),
	})
	// Inspect is non-destructive.
	if out, err := st.Inspect(context.Background(), "tok"); err != nil || out.UserID != "u" {
		t.Errorf("Inspect err=%v out=%v", err, out)
	}
	if out, err := st.Inspect(context.Background(), "tok"); err != nil || out.UserID != "u" {
		t.Errorf("second Inspect err=%v — Inspect must not consume", err)
	}
	// Delete is idempotent.
	if err := st.Delete(context.Background(), "tok"); err != nil {
		t.Errorf("Delete: %v", err)
	}
	if err := st.Delete(context.Background(), "tok"); err != nil {
		t.Errorf("second Delete err = %v want nil (idempotent)", err)
	}
	if _, err := st.Inspect(context.Background(), "tok"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("after Delete err = %v", err)
	}
}

func TestSQLiteRefresh_ExpiredIndistinguishable(t *testing.T) {
	t.Parallel()
	st, err := sqlite.NewRefreshTokenStore(freshSharedDSN(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	_ = st.Issue(context.Background(), "stale", &oauth.RefreshToken{
		UserID: "u", ClientID: "c", ExpiresAt: time.Now().Add(-time.Hour),
	})
	if _, err := st.Consume(context.Background(), "stale"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("Consume err = %v", err)
	}
	// Inspect also opportunistically deletes expired entries.
	if _, err := st.Inspect(context.Background(), "stale-2"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("Inspect on unknown err = %v", err)
	}
}

// ---------- oauth.RefreshTokenSubjectIndex ----------

func TestSQLiteRefresh_DeleteAllForSubject(t *testing.T) {
	t.Parallel()
	st, err := sqlite.NewRefreshTokenStore(freshSharedDSN(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	for _, tok := range []struct{ token, userID, clientID string }{
		{"a-1", "alice", "web"}, {"a-2", "alice", "web"},
		{"a-mob", "alice", "mobile"},
		{"b-1", "bob", "web"},
	} {
		_ = st.Issue(context.Background(), tok.token, &oauth.RefreshToken{
			UserID: tok.userID, ClientID: tok.clientID,
			ExpiresAt: time.Now().Add(time.Hour),
		})
	}

	// Filter by (alice, web) → 2 deletions.
	n, err := st.DeleteAllForSubject(context.Background(), "alice", "web")
	if err != nil {
		t.Fatalf("DeleteAllForSubject: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted = %d want 2", n)
	}
	// alice's mobile token + bob's web token survive.
	if _, err := st.Inspect(context.Background(), "a-mob"); err != nil {
		t.Errorf("alice/mobile lost: %v", err)
	}
	if _, err := st.Inspect(context.Background(), "b-1"); err != nil {
		t.Errorf("bob/web lost: %v", err)
	}
}

func TestSQLiteRefresh_DeleteAllForSubject_EmptyClient(t *testing.T) {
	t.Parallel()
	st, err := sqlite.NewRefreshTokenStore(freshSharedDSN(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	_ = st.Issue(context.Background(), "u-1", &oauth.RefreshToken{UserID: "u", ClientID: "a", ExpiresAt: time.Now().Add(time.Hour)})
	_ = st.Issue(context.Background(), "u-2", &oauth.RefreshToken{UserID: "u", ClientID: "b", ExpiresAt: time.Now().Add(time.Hour)})
	n, _ := st.DeleteAllForSubject(context.Background(), "u", "")
	if n != 2 {
		t.Errorf("empty client wipe = %d want 2", n)
	}
}

// ---------- oauth.RefreshTokenFamilyTracker ----------

func TestSQLiteRefresh_FamilyTracker_ReuseDetection(t *testing.T) {
	t.Parallel()
	st, err := sqlite.NewRefreshTokenStore(freshSharedDSN(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()

	exp := time.Now().Add(time.Hour)
	_ = st.Issue(ctx, "leaf-1", &oauth.RefreshToken{
		UserID: "u", ClientID: "c", FamilyID: "fam-x", ExpiresAt: exp,
	})
	// First consume succeeds; second is reuse.
	if _, err := st.Consume(ctx, "leaf-1"); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	tok, err := st.Consume(ctx, "leaf-1")
	if !errors.Is(err, oauth.ErrRefreshTokenReused) {
		t.Errorf("err = %v want oauth.ErrRefreshTokenReused", err)
	}
	if tok == nil || tok.FamilyID != "fam-x" {
		t.Errorf("expected family stamped on reuse RefreshToken: %+v", tok)
	}
}

func TestSQLiteRefresh_DeleteFamilyKillsAllAndForgetsLedger(t *testing.T) {
	t.Parallel()
	st, err := sqlite.NewRefreshTokenStore(freshSharedDSN(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)

	for _, tok := range []string{"t1", "t2", "t3"} {
		_ = st.Issue(ctx, tok, &oauth.RefreshToken{
			UserID: "u", ClientID: "c", FamilyID: "fam-1", ExpiresAt: exp,
		})
	}
	_ = st.Issue(ctx, "ux", &oauth.RefreshToken{
		UserID: "u", ClientID: "c", FamilyID: "fam-2", ExpiresAt: exp,
	})

	n, err := st.DeleteFamily(ctx, "fam-1")
	if err != nil {
		t.Fatalf("DeleteFamily: %v", err)
	}
	if n != 3 {
		t.Errorf("killed=%d want 3", n)
	}
	// fam-2 survives.
	if _, err := st.Consume(ctx, "ux"); err != nil {
		t.Errorf("fam-2 lost: %v", err)
	}
	// Reuse-detection ledger MUST be forgotten — second Consume of a
	// killed token returns plain not-found, NOT reuse.
	if _, err := st.Consume(ctx, "t1"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("post-DeleteFamily consume err = %v (want NotFound, no stale reuse)", err)
	}
}

// ---------- oauth.DeviceCodeStore ----------

func TestSQLiteDevice_FullStateMachine(t *testing.T) {
	t.Parallel()
	st, err := sqlite.NewDeviceCodeStore(freshSharedDSN(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	dc := &oauth.DeviceCode{
		DeviceCode: "DC", UserCode: "UC", ClientID: "c",
		Scopes: []string{"a"}, Interval: 5 * time.Second,
		ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := st.Issue(context.Background(), dc); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Lookup by both keys.
	if out, err := st.GetByDeviceCode(context.Background(), "DC"); err != nil || out.UserCode != "UC" {
		t.Errorf("GetByDeviceCode err=%v out=%v", err, out)
	}
	if out, err := st.GetByUserCode(context.Background(), "UC"); err != nil || out.DeviceCode != "DC" {
		t.Errorf("GetByUserCode err=%v out=%v", err, out)
	}
	// Approve flips state.
	if err := st.Approve(context.Background(), "UC", "u-1", "pw", map[string]string{"k": "v"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	out, _ := st.GetByDeviceCode(context.Background(), "DC")
	if !out.Approved || out.UserID != "u-1" || out.Provider != "pw" {
		t.Errorf("Approve not reflected: %+v", out)
	}
	if out.Attributes["k"] != "v" {
		t.Errorf("attributes not stored: %+v", out.Attributes)
	}
	// LastPoll round-trip.
	when := time.Unix(1234567890, 0).UTC()
	if err := st.UpdateLastPoll(context.Background(), "DC", when); err != nil {
		t.Fatalf("UpdateLastPoll: %v", err)
	}
	out, _ = st.GetByDeviceCode(context.Background(), "DC")
	if !out.LastPoll.Equal(when) {
		t.Errorf("LastPoll = %v want %v", out.LastPoll, when)
	}
	// Interval preserved.
	if out.Interval != 5*time.Second {
		t.Errorf("Interval lost: %v", out.Interval)
	}
	// Delete + Get after = not found.
	if err := st.Delete(context.Background(), "DC"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := st.GetByDeviceCode(context.Background(), "DC"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Errorf("after Delete err = %v", err)
	}
}

func TestSQLiteDevice_Deny(t *testing.T) {
	t.Parallel()
	st, err := sqlite.NewDeviceCodeStore(freshSharedDSN(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	_ = st.Issue(context.Background(), &oauth.DeviceCode{
		DeviceCode: "D", UserCode: "U", ClientID: "c",
		ExpiresAt: time.Now().Add(time.Minute),
	})
	if err := st.Deny(context.Background(), "U"); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	out, _ := st.GetByDeviceCode(context.Background(), "D")
	if !out.Denied {
		t.Errorf("Denied flag not set: %+v", out)
	}
}

func TestSQLiteDevice_ApproveDenyOnUnknownReturnsSentinel(t *testing.T) {
	t.Parallel()
	st, err := sqlite.NewDeviceCodeStore(freshSharedDSN(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.Approve(context.Background(), "ghost", "u", "p", nil); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Errorf("Approve err = %v", err)
	}
	if err := st.Deny(context.Background(), "ghost"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Errorf("Deny err = %v", err)
	}
}

func TestSQLiteDevice_UniqueUserCodeRejectsCollision(t *testing.T) {
	t.Parallel()
	st, err := sqlite.NewDeviceCodeStore(freshSharedDSN(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	first := &oauth.DeviceCode{
		DeviceCode: "D1", UserCode: "SAME", ClientID: "c",
		ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := st.Issue(context.Background(), first); err != nil {
		t.Fatalf("first Issue: %v", err)
	}
	second := &oauth.DeviceCode{
		DeviceCode: "D2", UserCode: "SAME", ClientID: "c",
		ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := st.Issue(context.Background(), second); err == nil {
		t.Error("duplicate user_code accepted — UNIQUE constraint missing")
	}
}
