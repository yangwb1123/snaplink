package sso_test

// rootcov_token_policy_enforce_test.go drives the three wave-3 token-policy
// enforcement dimensions through the REAL server (WithTokenPolicy), plus their
// byte-identical default when no policy is wired:
//   - max_refresh_depth: the refresh grant denies once a family has rotated to
//     the cap (oracle-safe invalid_grant).
//   - max_active_sessions: login refuses a new session at/over the per-user cap
//     (access_denied), BEFORE the session is minted (no orphan).
//   - require_renew: introspection reports a token past its renew fraction as
//     inactive (exercised at the wired Server seam with deterministic times).

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tokenpolicy"
	"github.com/yangwb1123/snaplink/domains/tokenpolicy/memory"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// tpolRefresh exchanges a refresh token at /token using the confidential client
// creds, returning the status + decoded body.
func tpolRefresh(t *testing.T, s *rcovServer, refreshToken string) (int, map[string]any) {
	t.Helper()
	return rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
	})
}

// tpolLogin performs a direct-mint login and returns the status + body (used for
// the paths that must assert a NON-200 outcome, which rcovDirectLogin can't).
func tpolLogin(t *testing.T, s *rcovServer) (int, map[string]any) {
	t.Helper()
	return rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"scope":      []string{"openid", "profile", "email"},
	})
}

// === Dimension 1: max_refresh_depth ===

// TestRcov_TokenPolicy_MaxRefreshDepthEnforced proves the refresh grant denies
// once the family's rotation depth reaches the cap. MaxRefreshDepth=2 allows two
// rotations (depths 0 and 1) then denies the third (depth 2) with the oracle-safe
// generic invalid_grant.
func TestRcov_TokenPolicy_MaxRefreshDepthEnforced(t *testing.T) {
	t.Parallel()
	store := memory.New(tokenpolicy.Policy{Name: "cap", MaxRefreshDepth: 2})
	s := rcovNewServer(t, sso.WithTokenPolicy(store))
	_, refresh := rcovDirectLogin(t, s) // generation-0 refresh token

	// Rotation 1 (depth 0 < 2): allowed, yields a generation-1 token.
	st, out := tpolRefresh(t, s, refresh)
	if st != http.StatusOK {
		t.Fatalf("rotation 1 status=%d body=%v, want 200", st, out)
	}
	refresh, _ = out["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("rotation 1 returned no refresh_token: %v", out)
	}
	// Rotation 2 (depth 1 < 2): allowed, yields a generation-2 token.
	st, out = tpolRefresh(t, s, refresh)
	if st != http.StatusOK {
		t.Fatalf("rotation 2 status=%d body=%v, want 200", st, out)
	}
	refresh, _ = out["refresh_token"].(string)
	// Rotation 3 (depth 2 >= 2): DENIED with the oracle-safe generic error.
	st, out = tpolRefresh(t, s, refresh)
	if st != http.StatusBadRequest {
		t.Fatalf("rotation 3 status=%d body=%v, want 400 (depth cap)", st, out)
	}
	if out["error"] != "invalid_grant" {
		t.Fatalf("rotation 3 error = %v, want invalid_grant (oracle-safe)", out["error"])
	}
}

// TestRcov_TokenPolicy_MaxRefreshDepthUnwiredUnlimited proves the default:
// without a policy store the same family rotates indefinitely (byte-identical).
func TestRcov_TokenPolicy_MaxRefreshDepthUnwiredUnlimited(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t) // no policy
	_, refresh := rcovDirectLogin(t, s)
	for i := 0; i < 4; i++ {
		st, out := tpolRefresh(t, s, refresh)
		if st != http.StatusOK {
			t.Fatalf("rotation %d status=%d body=%v, want 200 (unwired = unlimited)", i, st, out)
		}
		refresh, _ = out["refresh_token"].(string)
		if refresh == "" {
			t.Fatalf("rotation %d returned no refresh_token: %v", i, out)
		}
	}
}

// === Dimension 2: max_active_sessions ===

// TestRcov_TokenPolicy_MaxActiveSessionsEnforced proves login refuses a new
// session once the subject is at/over the per-(user,client) cap. Cap=2 allows
// two concurrent sessions then denies the third with access_denied.
func TestRcov_TokenPolicy_MaxActiveSessionsEnforced(t *testing.T) {
	t.Parallel()
	store := memory.New(tokenpolicy.Policy{Name: "cap", ClientID: rcovClient, MaxActiveSessions: 2})
	s := rcovNewServer(t, sso.WithTokenPolicy(store))

	if st, out := tpolLogin(t, s); st != http.StatusOK { // 0 existing -> allowed
		t.Fatalf("login 1 status=%d body=%v, want 200", st, out)
	}
	if st, out := tpolLogin(t, s); st != http.StatusOK { // 1 existing -> allowed
		t.Fatalf("login 2 status=%d body=%v, want 200", st, out)
	}
	// Third login: 2 live sessions >= cap 2 -> refused.
	st, out := tpolLogin(t, s)
	if st != http.StatusForbidden {
		t.Fatalf("login 3 status=%d body=%v, want 403 (session cap)", st, out)
	}
	if out["error"] != "access_denied" {
		t.Fatalf("login 3 error = %v, want access_denied", out["error"])
	}
	// The refused login must NOT have minted a session (enforced before mint).
	sessions, err := s.sessions.ListByUser(context.Background(), rcovUser)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("active sessions = %d, want 2 (refused login left no orphan)", len(sessions))
	}
}

// TestRcov_TokenPolicy_MaxActiveSessionsUnwiredUnlimited proves the default:
// without a policy store repeated logins all succeed (byte-identical).
func TestRcov_TokenPolicy_MaxActiveSessionsUnwiredUnlimited(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t) // no policy
	for i := 0; i < 4; i++ {
		if st, out := tpolLogin(t, s); st != http.StatusOK {
			t.Fatalf("login %d status=%d body=%v, want 200 (unwired = unlimited)", i, st, out)
		}
	}
	sessions, _ := s.sessions.ListByUser(context.Background(), rcovUser)
	if len(sessions) != 4 {
		t.Fatalf("active sessions = %d, want 4", len(sessions))
	}
}

// === Dimension 3: require_renew (Server seam, deterministic times) ===

// TestRcov_TokenPolicy_RequireRenewSeam drives the wired Server introspection
// seam with crafted issue/expiry times (deterministic, no wall-clock wait): a
// token past the require_renew fraction reports exceeded; a fresh one does not;
// and with no policy wired the seam is a byte-identical no-op.
func TestRcov_TokenPolicy_RequireRenewSeam(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now()
	// TTL 60s. issued 40s ago = 0.666 elapsed fraction.
	past := now.Add(-40 * time.Second)
	pastExp := past.Add(60 * time.Second)

	wired := sso.NewServer(sso.WithTokenPolicy(
		memory.New(tokenpolicy.Policy{Name: "renew", RequireRenewAfter: 0.5}),
	))
	exceeded, renewAt := wired.IntrospectionRenewExceeded(ctx, rcovClient, []string{"read"}, past, pastExp)
	if !exceeded {
		t.Fatalf("past-threshold token: want exceeded=true")
	}
	if renewAt.IsZero() || renewAt.After(now) {
		t.Fatalf("past-threshold renewAt = %v, want a non-zero time at or before now (%v)", renewAt, now)
	}
	// A fresh token (elapsed ~0) is NOT past the threshold — governance is not a
	// blanket deny. renewAt should still be reported (30s from now: 0.5 * 60s TTL).
	freshExceeded, freshRenewAt := wired.IntrospectionRenewExceeded(ctx, rcovClient, []string{"read"}, now, now.Add(60*time.Second))
	if freshExceeded {
		t.Fatalf("fresh token: want exceeded=false")
	}
	if wantRenewAt := now.Add(30 * time.Second); !freshRenewAt.Equal(wantRenewAt) {
		t.Fatalf("fresh token renewAt = %v, want %v", freshRenewAt, wantRenewAt)
	}

	// Default-off: no policy wired -> never exceeded, zero renewAt (byte-identical).
	off := sso.NewServer()
	offExceeded, offRenewAt := off.IntrospectionRenewExceeded(ctx, rcovClient, []string{"read"}, past, pastExp)
	if offExceeded {
		t.Fatalf("unwired: want exceeded=false (byte-identical)")
	}
	if !offRenewAt.IsZero() {
		t.Fatalf("unwired: want zero renewAt (byte-identical), got %v", offRenewAt)
	}
}
