package oauthwire_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystoreoauth"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	redisstore "github.com/yangwb1123/snaplink/infrastructure/redis"
	"github.com/yangwb1123/snaplink/protocols/oauth/oauthspi"
	"github.com/yangwb1123/snaplink/protocols/oauth/oauthwire"

	_ "modernc.org/sqlite"
)

// rtStore is the minimal SPI surface IssueRefreshToken needs: a real store
// that also implements the inspector so the test can read the record back.
type rtStore interface {
	oauthspi.RefreshTokenStore
	oauthspi.RefreshTokenInspector
}

// newRTStore builds one concrete refresh store per backend. sqlite needs a
// temp DSN; redis gets a fresh miniredis.
func newRTStore(t *testing.T, backend string) rtStore {
	t.Helper()
	switch backend {
	case "memory":
		return memorystoreoauth.NewMemoryRefreshTokenStore()
	case "sqlite":
		st, err := sqlite.NewRefreshTokenStore(filepath.Join(t.TempDir(), "rt.db"))
		if err != nil {
			t.Fatalf("sqlite.NewRefreshTokenStore: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		return st
	case "redis":
		mr, err := miniredis.Run()
		if err != nil {
			t.Fatalf("miniredis.Run: %v", err)
		}
		t.Cleanup(mr.Close)
		rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { _ = rdb.Close() })
		return redisstore.NewRefreshTokenStore(rdb)
	default:
		t.Fatalf("unknown backend %q", backend)
		return nil
	}
}

func issueParams(st oauthspi.RefreshTokenStore) oauthwire.IssueRefreshTokenParams {
	return oauthwire.IssueRefreshTokenParams{
		RefreshTokenTTL:   24 * time.Hour,
		RefreshTokenStore: st,
		UserID:            "alice",
		ClientID:          "app",
		Provider:          "password",
		Scopes:            []string{"openid", "offline_access"},
	}
}

// TestIssueRefreshToken_JTIRoundTrip is the store conformance contract for
// the refresh-introspect thumbprint: a fresh issue stamps a non-empty JTI
// that Inspect returns unchanged, on every refresh-store backend that exists
// (memory / redis / sqlite — there is no postgres refresh store).
func TestIssueRefreshToken_JTIRoundTrip(t *testing.T) {
	t.Parallel()
	for _, backend := range []string{"memory", "sqlite", "redis"} {
		t.Run(backend, func(t *testing.T) {
			t.Parallel()
			st := newRTStore(t, backend)
			token, err := oauthwire.IssueRefreshToken(context.Background(), issueParams(st))
			if err != nil {
				t.Fatalf("IssueRefreshToken: %v", err)
			}
			got, err := st.Inspect(context.Background(), token)
			if err != nil {
				t.Fatalf("Inspect: %v", err)
			}
			if got.JTI == "" {
				t.Fatal("fresh issue must stamp a non-empty JTI")
			}
			if got.FamilyID == "" {
				t.Error("fresh issue must also stamp a FamilyID (the JTI stamps in the same branch)")
			}
		})
	}
}

// TestIssueRefreshToken_RotationPropagatesJTIUnchanged is the rotation leg
// of the conformance contract: a rotation (FamilyID already set, JTI threaded
// from the parent) must persist the SAME JTI — the whole family then presents
// one stable thumbprint at the refresh-introspect Offer. A rotation of a
// pre-field parent (JTI "") must stay "" (no stamp, pre-feature behavior).
func TestIssueRefreshToken_RotationPropagatesJTIUnchanged(t *testing.T) {
	t.Parallel()
	st := memorystoreoauth.NewMemoryRefreshTokenStore()
	ctx := context.Background()

	// First issue mints the family + JTI.
	parent, err := oauthwire.IssueRefreshToken(ctx, issueParams(st))
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	parentRec, err := st.Inspect(ctx, parent)
	if err != nil {
		t.Fatalf("Inspect parent: %v", err)
	}

	// Rotate: same FamilyID + JTI threaded through RefreshAuthContext-shaped
	// params; the fresh-family branch is skipped, so JTI must be unchanged.
	p := issueParams(st)
	p.FamilyID = parentRec.FamilyID
	p.JTI = parentRec.JTI
	leaf, err := oauthwire.IssueRefreshToken(ctx, p)
	if err != nil {
		t.Fatalf("IssueRefreshToken (rotation): %v", err)
	}
	leafRec, err := st.Inspect(ctx, leaf)
	if err != nil {
		t.Fatalf("Inspect leaf: %v", err)
	}
	if leafRec.JTI != parentRec.JTI {
		t.Errorf("rotated JTI = %q, want parent's %q (stable thumbprint per family)", leafRec.JTI, parentRec.JTI)
	}
	if leafRec.FamilyID != parentRec.FamilyID {
		t.Errorf("rotated FamilyID = %q, want %q", leafRec.FamilyID, parentRec.FamilyID)
	}

	// Pre-field parent: FamilyID set but JTI empty (a rotation issued by a
	// binary that predates the field) must NOT be stamped — the fresh-family
	// branch is skipped, so the leaf stays thumbprint-less.
	p2 := issueParams(st)
	p2.FamilyID = "legacy-family"
	p2.JTI = ""
	legacy, err := oauthwire.IssueRefreshToken(ctx, p2)
	if err != nil {
		t.Fatalf("IssueRefreshToken (legacy rotation): %v", err)
	}
	legacyRec, err := st.Inspect(ctx, legacy)
	if err != nil {
		t.Fatalf("Inspect legacy: %v", err)
	}
	if legacyRec.JTI != "" {
		t.Errorf("legacy rotation JTI = %q, want '' (no retroactive stamp)", legacyRec.JTI)
	}
}
