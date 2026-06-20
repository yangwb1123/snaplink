package ssotest

import (
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	sso "github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/interfaces/web"
)

func portalFS(t *testing.T) fs.FS {
	t.Helper()
	sub, err := fs.Sub(web.PortalFS, "portal")
	if err != nil {
		t.Fatalf("portal sub-fs: %v", err)
	}
	return sub
}

func newPortalServer(t *testing.T, withPortal bool) *httptest.Server {
	t.Helper()
	opts := []sso.Option{
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
	}
	if withPortal {
		opts = append(opts, sso.WithSelfServicePortalFS(portalFS(t)))
	}
	srv := sso.NewServer(opts...)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs
}

// TestPortal_ServesSPA verifies the embedded self-service portal SPA is served
// at /portal/ when wired.
func TestPortal_ServesSPA(t *testing.T) {
	srv := newPortalServer(t, true)
	resp, err := http.Get(srv.URL + "/portal/")
	if err != nil {
		t.Fatalf("GET /portal/: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	// The real embedded index.html drives the /me* endpoints.
	for _, want := range []string{"Your account", "/me/password", "/sessions/me", "/me/mfa"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("portal SPA missing %q", want)
		}
	}
}

// TestPortal_NotMountedWithoutOption verifies /portal/ is absent (404) when the
// portal FS is not wired — byte-identical to a build without it.
func TestPortal_NotMountedWithoutOption(t *testing.T) {
	srv := newPortalServer(t, false)
	resp, err := http.Get(srv.URL + "/portal/")
	if err != nil {
		t.Fatalf("GET /portal/: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status=%d, want 404 without the portal option", resp.StatusCode)
	}
}
