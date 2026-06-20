package redis

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// mustJSON marshals v or fails the test — for seeding raw records directly into
// Redis to drive branches (e.g. expired-but-not-yet-evicted) the public Issue
// path intentionally refuses to create.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// downClient returns a go-redis client wired to an address whose server has
// been stopped, so every command returns a connection error. Used to exercise
// the `if err != nil` branches the happy-path tests never reach — and, for the
// fail-OPEN / fail-CLOSED stores, to pin which way a Redis outage tips.
func downClient(t *testing.T) *goredis.Client {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	rdb := goredis.NewClient(&goredis.Options{
		Addr:        mr.Addr(),
		DialTimeout: 200 * time.Millisecond,
		// Don't retry: a downed server should error promptly, not hang the test.
		MaxRetries: -1,
	})
	t.Cleanup(func() { _ = rdb.Close() })
	// Kill the server so every subsequent command fails to connect.
	mr.Close()
	return rdb
}

// TestPing_NilAndLive covers the Ping method on every store: the nil-guard
// branch (where present) returns an error rather than panicking, a Ping against
// a live miniredis succeeds, and a Ping against a down Redis errors. These
// methods are wired into sso.WithReadyCheck, so a nil-safe error path is the
// contract.
func TestPing_NilAndLive(t *testing.T) {
	_, rdb := newTestClient(t)
	ctx := context.Background()

	// Stores whose Ping has an explicit nil-guard: nil receiver must error.
	t.Run("nil-guarded", func(t *testing.T) {
		var ac *AuthCodeStore
		if err := ac.Ping(ctx); err == nil {
			t.Error("nil AuthCodeStore Ping must error")
		}
		var rt *RefreshTokenStore
		if err := rt.Ping(ctx); err == nil {
			t.Error("nil RefreshTokenStore Ping must error")
		}
		var sm *SessionManager
		if err := sm.Ping(ctx); err == nil {
			t.Error("nil SessionManager Ping must error")
		}
		var pr *PARStore
		if err := pr.Ping(ctx); err == nil {
			t.Error("nil PARStore Ping must error")
		}
		var jti *JTIReplayStore
		if err := jti.Ping(ctx); err == nil {
			t.Error("nil JTIReplayStore Ping must error")
		}
		var pp *PermissionProvider
		if err := pp.Ping(ctx); err == nil {
			t.Error("nil PermissionProvider Ping must error")
		}
	})

	// Live Ping must succeed for every store (covers the success branch).
	t.Run("live", func(t *testing.T) {
		pings := []func(context.Context) error{
			NewAuthCodeStore(rdb).Ping,
			NewRefreshTokenStore(rdb).Ping,
			NewSessionManager(rdb).Ping,
			NewPARStore(rdb).Ping,
			NewJTIReplayStore(rdb).Ping,
			NewPermissionProvider(rdb).Ping,
			NewClientStore(rdb).Ping,
			NewConsentStore(rdb).Ping,
			NewUserProvider(rdb).Ping,
			NewPasswordCredentialStore(rdb).Ping,
			NewCIBAStore(rdb).Ping,
			NewDeviceCodeStore(rdb).Ping,
			NewMFAChallengeStore(rdb).Ping,
		}
		for i, p := range pings {
			if err := p(ctx); err != nil {
				t.Errorf("live Ping #%d: %v", i, err)
			}
		}
	})

	// Down Redis: the non-nil-guarded stores' Ping must error via
	// rdb.Ping().Err().
	t.Run("down", func(t *testing.T) {
		down := downClient(t)
		if err := NewClientStore(down).Ping(ctx); err == nil {
			t.Error("ClientStore Ping against down redis must error")
		}
		if err := NewPasswordCredentialStore(down).Ping(ctx); err == nil {
			t.Error("PasswordCredentialStore Ping against down redis must error")
		}
		if err := NewUserProvider(down).Ping(ctx); err == nil {
			t.Error("UserProvider Ping against down redis must error")
		}
		if err := NewConsentStore(down).Ping(ctx); err == nil {
			t.Error("ConsentStore Ping against down redis must error")
		}
	})
}

// TestExpiredIssueIsNoOp covers the `ttl <= 0` already-expired branch shared by
// the single-use stores: an Issue/Put with a past ExpiresAt is a no-op success
// (never a no-TTL key that would pin Redis forever), and the subsequent read
// finds nothing.
func TestExpiredIssueIsNoOp(t *testing.T) {
	_, rdb := newTestClient(t)
	ctx := context.Background()
	past := time.Now().Add(-time.Minute)

	t.Run("auth_code", func(t *testing.T) {
		s := NewAuthCodeStore(rdb)
		if err := s.Issue(ctx, "ac", &oauth.AuthCode{ClientID: "c", ExpiresAt: past}); err != nil {
			t.Fatalf("issue expired: %v", err)
		}
		if _, err := s.Consume(ctx, "ac"); !errors.Is(err, oauth.ErrAuthCodeNotFound) {
			t.Fatalf("want not-found, got %v", err)
		}
	})

	t.Run("refresh", func(t *testing.T) {
		s := NewRefreshTokenStore(rdb)
		if err := s.Issue(ctx, "rt", &oauth.RefreshToken{UserID: "u", ClientID: "c", ExpiresAt: past}); err != nil {
			t.Fatalf("issue expired: %v", err)
		}
		if _, err := s.Consume(ctx, "rt"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
			t.Fatalf("want not-found, got %v", err)
		}
	})

	t.Run("device", func(t *testing.T) {
		s := NewDeviceCodeStore(rdb)
		dc := &oauth.DeviceCode{DeviceCode: "dc", UserCode: "uc", ClientID: "c", ExpiresAt: past}
		if err := s.Issue(ctx, dc); err != nil {
			t.Fatalf("issue expired: %v", err)
		}
		if _, err := s.GetByDeviceCode(ctx, "dc"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
			t.Fatalf("want not-found, got %v", err)
		}
	})

	t.Run("mfa", func(t *testing.T) {
		s := NewMFAChallengeStore(rdb)
		if err := s.Put(ctx, &spi.MFAChallenge{ID: "m", ExpiresAt: past}); err != nil {
			t.Fatalf("put expired: %v", err)
		}
		if _, err := s.Consume(ctx, "m"); !errors.Is(err, spi.ErrMFAChallengeNotFound) {
			t.Fatalf("want not-found, got %v", err)
		}
	})
}

// TestNilArgGuards covers the early-return validation branches that never touch
// Redis (nil/empty arguments collapse to the store's not-found / invalid
// sentinel).
func TestNilArgGuards(t *testing.T) {
	_, rdb := newTestClient(t)
	ctx := context.Background()

	if err := NewAuthCodeStore(rdb).Issue(ctx, "", nil); !errors.Is(err, oauth.ErrAuthCodeNotFound) {
		t.Errorf("auth_code Issue(empty): %v", err)
	}
	if err := NewRefreshTokenStore(rdb).Issue(ctx, "", nil); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("refresh Issue(empty): %v", err)
	}
	if err := NewDeviceCodeStore(rdb).Issue(ctx, &oauth.DeviceCode{}); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Errorf("device Issue(empty): %v", err)
	}
	if err := NewMFAChallengeStore(rdb).Put(ctx, &spi.MFAChallenge{}); !errors.Is(err, spi.ErrMFAChallengeNotFound) {
		t.Errorf("mfa Put(empty): %v", err)
	}
	if _, err := NewMFAChallengeStore(rdb).Consume(ctx, ""); !errors.Is(err, spi.ErrMFAChallengeNotFound) {
		t.Errorf("mfa Consume(empty): %v", err)
	}
	if _, err := NewPARStore(rdb).Issue(ctx, nil); !errors.Is(err, oauth.ErrPARNotFound) {
		t.Errorf("par Issue(nil): %v", err)
	}
	if _, err := NewCIBAStore(rdb).Issue(ctx, &oauth.CIBARequest{}); !errors.Is(err, oauth.ErrCIBARequestInvalid) {
		t.Errorf("ciba Issue(empty): %v", err)
	}
	if _, err := NewCIBAStore(rdb).Get(ctx, ""); !errors.Is(err, oauth.ErrCIBARequestNotFound) {
		t.Errorf("ciba Get(empty): %v", err)
	}
	if err := NewCIBAStore(rdb).SetStatus(ctx, "", oauth.CIBAApproved); !errors.Is(err, oauth.ErrCIBARequestNotFound) {
		t.Errorf("ciba SetStatus(empty): %v", err)
	}
	if err := NewCIBAStore(rdb).Delete(ctx, ""); err != nil {
		t.Errorf("ciba Delete(empty) must be no-op success: %v", err)
	}
}

// TestRedisErrorPaths drives the read/write error branches with a DOWN Redis,
// asserting BOTH the propagated error (fail-CLOSED stores) and the fail-OPEN
// stores' admit-on-outage contract. This is the single densest block of
// otherwise-uncovered code: every store's `if err != nil { return ...%w... }`.
func TestRedisErrorPaths(t *testing.T) {
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)

	t.Run("auth_code_fail_closed", func(t *testing.T) {
		s := NewAuthCodeStore(downClient(t))
		if err := s.Issue(ctx, "c", &oauth.AuthCode{ClientID: "x", ExpiresAt: exp}); err == nil {
			t.Error("Issue against down redis must error (fail-closed)")
		}
		// GETDEL error (not redis.Nil) must surface, not collapse to not-found.
		if _, err := s.Consume(ctx, "c"); err == nil || errors.Is(err, oauth.ErrAuthCodeNotFound) {
			t.Errorf("Consume against down redis: want transport error, got %v", err)
		}
	})

	t.Run("refresh_fail_closed", func(t *testing.T) {
		s := NewRefreshTokenStore(downClient(t))
		if err := s.Issue(ctx, "rt", &oauth.RefreshToken{UserID: "u", ClientID: "c", ExpiresAt: exp}); err == nil {
			t.Error("Issue must error")
		}
		if _, err := s.Consume(ctx, "rt"); err == nil {
			t.Error("Consume must error")
		}
		if _, err := s.Inspect(ctx, "rt"); err == nil {
			t.Error("Inspect must error")
		}
		if err := s.Delete(ctx, "rt"); err == nil {
			t.Error("Delete must error")
		}
		if _, err := s.DeleteAllForSubject(ctx, "u", "c"); err == nil {
			t.Error("DeleteAllForSubject must error")
		}
		if _, err := s.DeleteAllForSubject(ctx, "u", ""); err == nil {
			t.Error("DeleteAllForSubject(all-clients SCAN) must error")
		}
		if _, err := s.CountForSubject(ctx, "u", "c"); err == nil {
			t.Error("CountForSubject must error")
		}
		if _, err := s.CountForSubject(ctx, "u", ""); err == nil {
			t.Error("CountForSubject(all-clients SCAN) must error")
		}
		if _, err := s.DeleteAllForClient(ctx, "c"); err == nil {
			t.Error("DeleteAllForClient must error")
		}
		if _, err := s.DeleteFamily(ctx, "fam"); err == nil {
			t.Error("DeleteFamily must error")
		}
	})

	t.Run("par_fail_closed", func(t *testing.T) {
		s := NewPARStore(downClient(t))
		if _, err := s.Issue(ctx, &oauth.PARRequest{ExpiresAt: exp}); err == nil {
			t.Error("Issue must error")
		}
		if _, err := s.Consume(ctx, "uri"); err == nil || errors.Is(err, oauth.ErrPARNotFound) {
			t.Errorf("Consume: want transport error, got %v", err)
		}
	})

	t.Run("mfa_fail_closed", func(t *testing.T) {
		s := NewMFAChallengeStore(downClient(t))
		if err := s.Put(ctx, &spi.MFAChallenge{ID: "m", ExpiresAt: exp}); err == nil {
			t.Error("Put must error")
		}
		if _, err := s.Consume(ctx, "m"); err == nil || errors.Is(err, spi.ErrMFAChallengeNotFound) {
			t.Errorf("Consume: want transport error, got %v", err)
		}
	})

	t.Run("device_fail_closed", func(t *testing.T) {
		s := NewDeviceCodeStore(downClient(t))
		if err := s.Issue(ctx, &oauth.DeviceCode{DeviceCode: "d", UserCode: "u", ClientID: "c", ExpiresAt: exp}); err == nil {
			t.Error("Issue must error")
		}
		if _, err := s.GetByDeviceCode(ctx, "d"); err == nil || errors.Is(err, oauth.ErrDeviceCodeNotFound) {
			t.Errorf("GetByDeviceCode: want transport error, got %v", err)
		}
		if _, err := s.GetByUserCode(ctx, "u"); err == nil || errors.Is(err, oauth.ErrDeviceCodeNotFound) {
			t.Errorf("GetByUserCode: want transport error, got %v", err)
		}
		if err := s.Approve(ctx, "u", "uid", "p", nil); err == nil {
			t.Error("Approve must error")
		}
		if err := s.UpdateLastPoll(ctx, "d", time.Now()); err == nil {
			t.Error("UpdateLastPoll must error")
		}
		if err := s.Delete(ctx, "d"); err == nil {
			t.Error("Delete must error")
		}
	})

	t.Run("ciba_fail_closed", func(t *testing.T) {
		s := NewCIBAStore(downClient(t))
		if _, err := s.Issue(ctx, &oauth.CIBARequest{ClientID: "c", SubjectID: "u", ExpiresAt: exp}); err == nil {
			t.Error("Issue must error")
		}
		if _, err := s.Get(ctx, "id"); err == nil || errors.Is(err, oauth.ErrCIBARequestNotFound) {
			t.Errorf("Get: want transport error, got %v", err)
		}
		if err := s.SetStatus(ctx, "id", oauth.CIBAApproved); err == nil {
			t.Error("SetStatus must error")
		}
		if err := s.UpdateLastPoll(ctx, "id", time.Now()); err == nil {
			t.Error("UpdateLastPoll must error")
		}
		if err := s.Delete(ctx, "id"); err == nil {
			t.Error("Delete must error")
		}
	})

	t.Run("session_fail_closed", func(t *testing.T) {
		s := NewSessionManager(downClient(t))
		if _, err := s.Create(ctx, "u"); err == nil {
			t.Error("Create must error")
		}
		if _, err := s.Get(ctx, "sid"); err == nil || errors.Is(err, sso.ErrSessionNotFound) {
			t.Errorf("Get: want transport error, got %v", err)
		}
		if _, err := s.Refresh(ctx, "sid"); err == nil || errors.Is(err, sso.ErrSessionNotFound) {
			t.Errorf("Refresh: want transport error, got %v", err)
		}
		if err := s.Destroy(ctx, "sid"); err == nil {
			t.Error("Destroy must error")
		}
		if _, err := s.ListByUser(ctx, "u"); err == nil {
			t.Error("ListByUser must error")
		}
		if _, err := s.ListAll(ctx); err == nil {
			t.Error("ListAll must error")
		}
	})

	t.Run("ratelimit_fail_OPEN", func(t *testing.T) {
		// The hot-path defense layer admits on a Redis outage rather than
		// 503-ing real users (the authenticator still gates credentials).
		l := NewLimiter(downClient(t), 1, time.Minute, "")
		ok, retry := l.Allow("k")
		if !ok || retry != 0 {
			t.Fatalf("rate limiter must fail-OPEN on redis error, got ok=%v retry=%v", ok, retry)
		}
	})

	t.Run("jti_fail_OPEN", func(t *testing.T) {
		// Replay defense fails open: a backend hiccup returns (firstSighting,
		// err) so it never blocks a valid request.
		s := NewJTIReplayStore(downClient(t))
		first, err := s.MarkSeen(ctx, "jti", exp)
		if !first || err == nil {
			t.Fatalf("jti MarkSeen must fail-OPEN (true, err), got first=%v err=%v", first, err)
		}
	})

	t.Run("clients_fail_closed", func(t *testing.T) {
		s := NewClientStore(downClient(t))
		if _, err := s.Get(ctx, "c"); err == nil || errors.Is(err, sso.ErrNoSuchClient) {
			t.Errorf("Get: want transport error, got %v", err)
		}
		if err := s.Add(ctx, &sso.Client{ID: "c"}); err == nil {
			t.Error("Add must error")
		}
		if err := s.Update(ctx, &sso.Client{ID: "c"}); err == nil {
			t.Error("Update must error")
		}
		if err := s.Delete(ctx, "c"); err == nil {
			t.Error("Delete must error")
		}
		if _, err := s.List(ctx); err == nil {
			t.Error("List must error")
		}
		if _, err := s.RotateSecret(ctx, "c"); err == nil {
			t.Error("RotateSecret must error")
		}
		if err := s.ValidateSecret(ctx, "c", "s"); err == nil {
			t.Error("ValidateSecret must error")
		}
	})

	t.Run("users_fail_closed", func(t *testing.T) {
		p := NewUserProvider(downClient(t))
		if _, err := p.GetByID(ctx, "id"); err == nil || errors.Is(err, sso.ErrNoSuchUser) {
			t.Errorf("GetByID: want transport error, got %v", err)
		}
		if _, err := p.GetByExternalID(ctx, "prov", "ext"); err == nil || errors.Is(err, sso.ErrNoSuchUser) {
			t.Errorf("GetByExternalID: want transport error, got %v", err)
		}
		if err := p.CreateOrUpdate(ctx, &sso.User{ID: "u"}); err == nil {
			t.Error("CreateOrUpdate must error")
		}
		if _, err := p.List(ctx); err == nil {
			t.Error("List must error")
		}
		if err := p.Delete(ctx, "id"); err == nil {
			t.Error("Delete must error")
		}
	})

	t.Run("consent_fail_closed", func(t *testing.T) {
		s := NewConsentStore(downClient(t))
		if err := s.RecordConsent(ctx, sso.ConsentGrant{UserID: "u", ClientID: "c"}); err == nil {
			t.Error("RecordConsent must error")
		}
		if _, err := s.GetConsent(ctx, "u", "c"); err == nil || errors.Is(err, sso.ErrNoConsentGrant) {
			t.Errorf("GetConsent: want transport error, got %v", err)
		}
		if err := s.RevokeConsent(ctx, "u", "c"); err == nil {
			t.Error("RevokeConsent must error")
		}
		if _, err := s.ListByUser(ctx, "u"); err == nil {
			t.Error("ListByUser must error")
		}
	})

	t.Run("password_fail_closed", func(t *testing.T) {
		s := NewPasswordCredentialStore(downClient(t))
		if err := s.SetPassword(ctx, "u", "pw"); err == nil {
			t.Error("SetPassword must error")
		}
		if err := s.SetPasswordHash(ctx, "u", "$2a$10$abcdefghijklmnopqrstuv"); err == nil {
			t.Error("SetPasswordHash must error")
		}
		// VerifyPassword on a real Get error (not redis.Nil) propagates.
		if err := s.VerifyPassword(ctx, "u", "pw"); err == nil {
			t.Error("VerifyPassword must propagate a transport error")
		}
	})

	t.Run("permissions_fail_closed", func(t *testing.T) {
		p := NewPermissionProvider(downClient(t))
		role := permissions.Role{Code: "admin", Permissions: []string{"x:read"}}
		if err := p.AddRole(ctx, "c", role); err == nil {
			t.Error("AddRole must error")
		}
		if err := p.UpdateRole(ctx, "c", role); err == nil {
			t.Error("UpdateRole must error")
		}
		if err := p.RemoveRole(ctx, "c", "admin"); err == nil {
			t.Error("RemoveRole must error")
		}
		if _, err := p.ListAllRoles(ctx, "c"); err == nil {
			t.Error("ListAllRoles must error")
		}
		if err := p.AssignRoles(ctx, "u", "c", []string{"admin"}); err == nil {
			t.Error("AssignRoles must error")
		}
		if err := p.UnassignRoles(ctx, "u", "c", []string{"admin"}); err == nil {
			t.Error("UnassignRoles must error")
		}
		if err := p.AddRoleToUser(ctx, "u", "c", "admin"); err == nil {
			t.Error("AddRoleToUser must error")
		}
		if _, err := p.ListAssignments(ctx, "c"); err == nil {
			t.Error("ListAssignments must error")
		}
		if err := p.SetMenus(ctx, "c", permissions.MenuTree{}); err == nil {
			t.Error("SetMenus must error")
		}
		if _, err := p.GetMenus(ctx, "c"); err == nil {
			t.Error("GetMenus must error")
		}
		if _, err := p.Roles(ctx, "u", "c"); err == nil {
			t.Error("Roles must error")
		}
		if _, err := p.Permissions(ctx, "u", "c"); err == nil {
			t.Error("Permissions must error")
		}
		if _, err := p.Menus(ctx, "u", "c"); err == nil {
			t.Error("Menus must error")
		}
	})
}

// TestRefreshInspectExpiredGC covers Inspect's expired-token branch: an
// expired-but-not-yet-evicted token is opportunistically GCed and reported
// not-found (the eviction-lag defense, mirroring the SQLite peer).
func TestRefreshInspectExpiredGC(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewRefreshTokenStore(rdb)
	ctx := context.Background()

	// Seed the active key directly with a non-positive remaining lifetime so
	// the key exists but IsExpired() is true (Issue would no-op an expired one).
	tok := "stale-rt"
	info := &oauth.RefreshToken{UserID: "u", ClientID: "c", ExpiresAt: time.Now().Add(-time.Second), FamilyID: "fam"}
	if err := rdb.Set(ctx, rtKey(tok), mustJSON(t, info), time.Minute).Err(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := s.Inspect(ctx, tok); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Fatalf("inspect expired: want not-found, got %v", err)
	}
	// The active key must have been GCed by Inspect.
	if n, _ := rdb.Exists(ctx, rtKey(tok)).Result(); n != 0 {
		t.Fatal("Inspect must GC the expired active key")
	}
}

// TestRefreshConsumeExpiredCollapses covers Consume's IsExpired() branch on a
// successfully-fetched-but-logically-expired token (the eviction-lag window):
// it must collapse to not-found, not return the stale token.
func TestRefreshConsumeExpiredCollapses(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewRefreshTokenStore(rdb)
	ctx := context.Background()

	tok := "consume-stale"
	info := &oauth.RefreshToken{UserID: "u", ClientID: "c", ExpiresAt: time.Now().Add(-time.Second)}
	if err := rdb.Set(ctx, rtKey(tok), mustJSON(t, info), time.Minute).Err(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := s.Consume(ctx, tok); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Fatalf("consume expired: want not-found, got %v", err)
	}
}

// TestRefreshOptOutEmptyFamily covers the empty-FamilyID opt-out: with no
// family marker written at Issue, a replay after Consume degrades to vanilla
// not-found (NOT a reuse event), matching the SQLite peer.
func TestRefreshOptOutEmptyFamily(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewRefreshTokenStore(rdb)
	ctx := context.Background()

	tok := "no-family"
	if err := s.Issue(ctx, tok, &oauth.RefreshToken{UserID: "u", ClientID: "c", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := s.Consume(ctx, tok); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	// Replay: no family marker -> plain not-found, never ErrRefreshTokenReused.
	if _, err := s.Consume(ctx, tok); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Fatalf("replay of opted-out token: want not-found, got %v", err)
	}
}

// TestRefreshBulkRevokeEmptyArgs covers the empty-arg short-circuits on the
// bulk operations (userID/clientID empty => zero, no Redis touch).
func TestRefreshBulkRevokeEmptyArgs(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewRefreshTokenStore(rdb)
	ctx := context.Background()

	if n, err := s.DeleteAllForSubject(ctx, "", "c"); err != nil || n != 0 {
		t.Errorf("DeleteAllForSubject(empty user): n=%d err=%v", n, err)
	}
	if n, err := s.CountForSubject(ctx, "", "c"); err != nil || n != 0 {
		t.Errorf("CountForSubject(empty user): n=%d err=%v", n, err)
	}
	if n, err := s.DeleteAllForClient(ctx, ""); err != nil || n != 0 {
		t.Errorf("DeleteAllForClient(empty): n=%d err=%v", n, err)
	}
	if n, err := s.DeleteFamily(ctx, ""); err != nil || n != 0 {
		t.Errorf("DeleteFamily(empty): n=%d err=%v", n, err)
	}
}

// TestRefreshWithFamilyTTLOption covers the WithFamilyTTL option and its
// non-positive default-floor branch in NewRefreshTokenStore.
func TestRefreshWithFamilyTTLOption(t *testing.T) {
	_, rdb := newTestClient(t)
	if s := NewRefreshTokenStore(rdb, WithFamilyTTL(time.Hour)); s.familyTTL != time.Hour {
		t.Errorf("WithFamilyTTL(1h): got %v", s.familyTTL)
	}
	// Non-positive option value floors back to the 30d default.
	if s := NewRefreshTokenStore(rdb, WithFamilyTTL(-1)); s.familyTTL != 30*24*time.Hour {
		t.Errorf("WithFamilyTTL(neg) must floor to default, got %v", s.familyTTL)
	}
}

// TestSessionWithTTLOptionFloor covers the WithSessionTTL non-positive floor in
// NewSessionManager.
func TestSessionWithTTLOptionFloor(t *testing.T) {
	_, rdb := newTestClient(t)
	if s := NewSessionManager(rdb, WithSessionTTL(-1)); s.ttl != sso.DefaultSessionDuration {
		t.Errorf("WithSessionTTL(neg) must floor to default, got %v", s.ttl)
	}
}

// TestLimiterConstructorFloors covers the limit<1 and window<=0 flooring in
// NewLimiter and the burst<1 / sub-second-window flooring in NewLimiterFromRate.
func TestLimiterConstructorFloors(t *testing.T) {
	_, rdb := newTestClient(t)

	// limit<1 -> 1, window<=0 -> 1s.
	l := NewLimiter(rdb, 0, 0, "")
	if l.limit != 1 || l.window != time.Second {
		t.Fatalf("NewLimiter floors: limit=%d window=%v", l.limit, l.window)
	}

	// burst<1 -> 1.
	l = NewLimiterFromRate(rdb, 100, 0, "")
	if l.limit != 1 {
		t.Fatalf("NewLimiterFromRate burst floor: limit=%d", l.limit)
	}

	// A very high perSecond yields a sub-1ns window that must floor to 1s.
	l = NewLimiterFromRate(rdb, 1e18, 1, "")
	if l.window != time.Second {
		t.Fatalf("NewLimiterFromRate tiny-window floor: window=%v", l.window)
	}
}

// TestDeviceUserCodePointerRollback covers Issue's user_code pointer write + the
// GetByUserCode pointer-deref path, plus a dangling pointer: a user_code whose
// canonical record is gone resolves to not-found.
func TestDeviceUserCodePointerRollback(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewDeviceCodeStore(rdb)
	ctx := context.Background()

	dc := &oauth.DeviceCode{DeviceCode: "DEV", UserCode: "USR", ClientID: "c", ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.Issue(ctx, dc); err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Pointer dereference resolves to the canonical record.
	got, err := s.GetByUserCode(ctx, "USR")
	if err != nil || got.DeviceCode != "DEV" {
		t.Fatalf("GetByUserCode: got %+v err %v", got, err)
	}

	// Delete the canonical record out of band, leaving a dangling pointer.
	if err := rdb.Del(ctx, deviceCodeKey("DEV")).Err(); err != nil {
		t.Fatalf("del record: %v", err)
	}
	if _, err := s.GetByUserCode(ctx, "USR"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Fatalf("dangling pointer: want not-found, got %v", err)
	}

	// Unknown user_code (no pointer) -> not-found via resolveUserCode redis.Nil.
	if _, err := s.GetByUserCode(ctx, "NOPE"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Fatalf("unknown user_code: want not-found, got %v", err)
	}
}

// TestDeviceDeleteMissingAndUnparseable covers Delete's redis.Nil (missing ->
// idempotent no-op) branch and the unparseable-record fallback branch.
func TestDeviceDeleteMissingAndUnparseable(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewDeviceCodeStore(rdb)
	ctx := context.Background()

	// Missing code: idempotent success (redis.Nil path).
	if err := s.Delete(ctx, "ghost"); err != nil {
		t.Fatalf("Delete(missing): %v", err)
	}

	// Unparseable record: Delete must still drop the device_code key.
	if err := rdb.Set(ctx, deviceCodeKey("junk"), "not-json", time.Minute).Err(); err != nil {
		t.Fatalf("seed junk: %v", err)
	}
	if err := s.Delete(ctx, "junk"); err != nil {
		t.Fatalf("Delete(unparseable): %v", err)
	}
	if n, _ := rdb.Exists(ctx, deviceCodeKey("junk")).Result(); n != 0 {
		t.Fatal("Delete must drop the unparseable device_code key")
	}
}

// TestDeviceGetExpiredGC covers getByDeviceCode's IsExpired() eviction-lag
// branch: a logically-expired-but-not-yet-TTL-evicted record is GCed (both
// keys) and reported not-found.
func TestDeviceGetExpiredGC(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewDeviceCodeStore(rdb)
	ctx := context.Background()

	dc := &oauth.DeviceCode{DeviceCode: "EXP", UserCode: "EU", ClientID: "c", ExpiresAt: time.Now().Add(-time.Second)}
	// Seed directly with a live key TTL but a past ExpiresAt.
	if err := rdb.Set(ctx, deviceCodeKey("EXP"), mustJSON(t, dc), time.Minute).Err(); err != nil {
		t.Fatalf("seed record: %v", err)
	}
	if err := rdb.Set(ctx, userCodeKey("EU"), "EXP", time.Minute).Err(); err != nil {
		t.Fatalf("seed pointer: %v", err)
	}
	if _, err := s.GetByDeviceCode(ctx, "EXP"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Fatalf("expired get: want not-found, got %v", err)
	}
	if n, _ := rdb.Exists(ctx, deviceCodeKey("EXP")).Result(); n != 0 {
		t.Fatal("expired record must be GCed")
	}
	if n, _ := rdb.Exists(ctx, userCodeKey("EU")).Result(); n != 0 {
		t.Fatal("expired record's pointer must be GCed")
	}
}

// TestCIBAGetExpiredGC covers Get's IsExpired() GC branch and SetStatus /
// UpdateLastPoll / Delete behavior on missing entries.
func TestCIBAGetExpiredGC(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewCIBAStore(rdb)
	ctx := context.Background()

	rec := &oauth.CIBARequest{AuthReqID: "EXP", ClientID: "c", SubjectID: "u", Status: oauth.CIBAPending, ExpiresAt: time.Now().Add(-time.Second)}
	if err := rdb.Set(ctx, cibaKey("EXP"), mustJSON(t, rec), time.Minute).Err(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := s.Get(ctx, "EXP"); !errors.Is(err, oauth.ErrCIBARequestNotFound) {
		t.Fatalf("expired get: want not-found, got %v", err)
	}
	if n, _ := rdb.Exists(ctx, cibaKey("EXP")).Result(); n != 0 {
		t.Fatal("expired ciba record must be GCed")
	}

	// SetStatus on a missing/expired entry surfaces not-found (via the pre-Get).
	if err := s.SetStatus(ctx, "EXP", oauth.CIBAApproved); !errors.Is(err, oauth.ErrCIBARequestNotFound) {
		t.Fatalf("SetStatus(expired): want not-found, got %v", err)
	}
	// UpdateLastPoll on a missing entry is a silent no-op success.
	if err := s.UpdateLastPoll(ctx, "missing", time.Now()); err != nil {
		t.Fatalf("UpdateLastPoll(missing): want nil, got %v", err)
	}
	// Delete of a missing entry is idempotent.
	if err := s.Delete(ctx, "missing"); err != nil {
		t.Fatalf("Delete(missing): %v", err)
	}
}

// TestCIBAIssueDefaultTTL covers Issue's `ttl <= 0 => DefaultCIBARequestTTL`
// branch (a past ExpiresAt does NOT no-op for CIBA — it falls back to the
// default TTL, unlike the single-use code stores).
func TestCIBAIssueDefaultTTL(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewCIBAStore(rdb)
	ctx := context.Background()

	id, err := s.Issue(ctx, &oauth.CIBARequest{ClientID: "c", SubjectID: "u", ExpiresAt: time.Now().Add(-time.Minute)})
	if err != nil {
		t.Fatalf("issue with past expiry: %v", err)
	}
	// The key was persisted with a positive TTL (default), so it exists.
	if n, _ := rdb.Exists(ctx, cibaKey(id)).Result(); n != 1 {
		t.Fatal("CIBA Issue with past expiry must persist under the default TTL")
	}
}

// TestPARIssueDefaultTTL covers PAR Issue's `ttl <= 0 => DefaultPARTTL` branch.
func TestPARIssueDefaultTTL(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewPARStore(rdb)
	ctx := context.Background()

	uri, err := s.Issue(ctx, &oauth.PARRequest{ExpiresAt: time.Now().Add(-time.Minute)})
	if err != nil {
		t.Fatalf("issue with past expiry: %v", err)
	}
	if n, _ := rdb.Exists(ctx, parKey(uri)).Result(); n != 1 {
		t.Fatal("PAR Issue with past expiry must persist under the default TTL")
	}
}

// TestJTIPastExpiryFloor covers MarkSeen's `ttl <= 0 => 1s floor` branch: a jti
// whose expiry is already past still records (so an immediate replay is caught).
func TestJTIPastExpiryFloor(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewJTIReplayStore(rdb)
	ctx := context.Background()

	first, err := s.MarkSeen(ctx, "past-jti", time.Now().Add(-time.Hour))
	if err != nil || !first {
		t.Fatalf("first sighting of past-expiry jti: first=%v err=%v", first, err)
	}
	// Immediate replay within the 1s floor is caught.
	again, err := s.MarkSeen(ctx, "past-jti", time.Now().Add(-time.Hour))
	if err != nil || again {
		t.Fatalf("replay of past-expiry jti: want caught, first=%v err=%v", again, err)
	}
}

// TestPermissionsMenusEdges covers SetMenus' nil-menus normalization, GetMenus'
// redis.Nil empty-tree branch, and Menus' no-roles degrade-to-empty branch.
func TestPermissionsMenusEdges(t *testing.T) {
	_, rdb := newTestClient(t)
	p := NewPermissionProvider(rdb)
	ctx := context.Background()

	// SetMenus(nil) normalizes to an empty tree (no error, persists empty).
	if err := p.SetMenus(ctx, "c", nil); err != nil {
		t.Fatalf("SetMenus(nil): %v", err)
	}
	// GetMenus on a client with no menus key -> empty tree (redis.Nil branch).
	tree, err := p.GetMenus(ctx, "other-client")
	if err != nil || tree == nil || len(tree) != 0 {
		t.Fatalf("GetMenus(absent): tree=%v err=%v", tree, err)
	}

	// Menus for a user with no roles -> empty filtered tree (the no-roles
	// degrade-to-empty branch), after seeding a non-empty tree.
	full := permissions.MenuTree{{ID: "m1", Name: "Home", Permission: "x:read"}}
	if err := p.SetMenus(ctx, "c", full); err != nil {
		t.Fatalf("SetMenus: %v", err)
	}
	filtered, err := p.Menus(ctx, "no-roles-user", "c")
	if err != nil || len(filtered) != 0 {
		t.Fatalf("Menus(no-roles): %v err=%v", filtered, err)
	}
}

// TestPermissionsRolesUnknownUser covers Roles/Permissions returning
// ErrUserNotFound when the user holds no assignments.
func TestPermissionsRolesUnknownUser(t *testing.T) {
	_, rdb := newTestClient(t)
	p := NewPermissionProvider(rdb)
	ctx := context.Background()

	if _, err := p.Roles(ctx, "ghost", "c"); !errors.Is(err, permissions.ErrUserNotFound) {
		t.Fatalf("Roles(unknown): want ErrUserNotFound, got %v", err)
	}
	if _, err := p.Permissions(ctx, "ghost", "c"); !errors.Is(err, permissions.ErrUserNotFound) {
		t.Fatalf("Permissions(unknown): want ErrUserNotFound, got %v", err)
	}
}

// TestClientValidateSecretInactive covers ValidateSecret's inactive-client
// branch (correct secret but Active==false rejects) and the wrong-secret branch.
func TestClientValidateSecretInactive(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewClientStore(rdb)
	ctx := context.Background()

	// Inactive client with a known secret.
	if err := s.Add(ctx, &sso.Client{ID: "inact", Secret: "topsecret", Active: false}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := s.ValidateSecret(ctx, "inact", "topsecret"); err == nil {
		t.Fatal("ValidateSecret on an inactive client must error even with the right secret")
	}

	// Active client, wrong secret.
	if err := s.Add(ctx, &sso.Client{ID: "act", Secret: "rightpw", Active: true}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := s.ValidateSecret(ctx, "act", "wrongpw"); err == nil {
		t.Fatal("ValidateSecret with the wrong secret must error")
	}
	// Active client, right secret -> ok.
	if err := s.ValidateSecret(ctx, "act", "rightpw"); err != nil {
		t.Fatalf("ValidateSecret happy path: %v", err)
	}
}

// TestClientUnmarshalNilRecord covers unmarshalClient's nil-client guard via a
// directly-seeded record whose embedded client is null.
func TestClientUnmarshalNilRecord(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewClientStore(rdb)
	ctx := context.Background()

	if err := rdb.Set(ctx, clientKey("bad"), `{"client":null}`, 0).Err(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := s.Get(ctx, "bad"); err == nil {
		t.Fatal("Get on a record with a nil embedded client must error")
	}
}

// TestPasswordSetHashRejectsPlaintext covers SetPasswordHash's non-bcrypt
// rejection branch and the empty-userID guard on both setters.
func TestPasswordSetHashRejectsPlaintext(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewPasswordCredentialStore(rdb)
	ctx := context.Background()

	if err := s.SetPasswordHash(ctx, "u", "not-a-bcrypt-hash"); err == nil {
		t.Fatal("SetPasswordHash must reject a non-bcrypt value")
	}
	if err := s.SetPassword(ctx, "", "pw"); !errors.Is(err, core.ErrPasswordMismatch) {
		t.Fatalf("SetPassword(empty user): %v", err)
	}
	if err := s.SetPasswordHash(ctx, "", "$2a$10$xxxxxxxxxxxxxxxxxxxxxx"); !errors.Is(err, core.ErrPasswordMismatch) {
		t.Fatalf("SetPasswordHash(empty user): %v", err)
	}
}

// TestUserGetByExternalIDStalePointer covers GetByExternalID's stale-pointer
// guard: a pointer key that resolves to a user no longer carrying that external
// identity returns not-found. Also covers the empty-arg short-circuit.
func TestUserGetByExternalIDStalePointer(t *testing.T) {
	_, rdb := newTestClient(t)
	p := NewUserProvider(rdb)
	ctx := context.Background()

	// Create a user with an external identity.
	u := &sso.User{ID: "u1", Provider: "github", ExternalID: "gh-123"}
	if err := p.CreateOrUpdate(ctx, u); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Forge a stale pointer: a different provider's pointer aimed at u1.
	if err := rdb.Set(ctx, userExtKey("gitlab", "gl-999"), "u1", 0).Err(); err != nil {
		t.Fatalf("forge pointer: %v", err)
	}
	if _, err := p.GetByExternalID(ctx, "gitlab", "gl-999"); !errors.Is(err, sso.ErrNoSuchUser) {
		t.Fatalf("stale pointer: want ErrNoSuchUser, got %v", err)
	}

	// Empty provider/externalID short-circuits to not-found.
	if _, err := p.GetByExternalID(ctx, "", "x"); !errors.Is(err, sso.ErrNoSuchUser) {
		t.Fatalf("empty provider: %v", err)
	}
}
