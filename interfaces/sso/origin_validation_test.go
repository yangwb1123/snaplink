package sso_test

// origin_validation_test.go verifies the Origin header validation
// defense-in-depth CSRF protection on the /auth/login endpoint.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/cors"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// TestLogin_OriginValidation verifies that the /auth/login endpoint validates
// the Origin header against the CORS policy as defense-in-depth CSRF protection.
func TestLogin_OriginValidation(t *testing.T) {
	t.Parallel()

	// Create a minimal server with CORS policy
	users := defaultimpl.NewMemoryUserProvider()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "test-client", Secret: "test-secret", RedirectURIs: []string{"https://app.example.com/callback"},
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
		Active: true,
	})

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithCORS(cors.Policy{
			AllowedOrigins: []string{"https://app.example.com"},
		}),
	)

	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	tests := []struct {
		name                string
		origin              string
		expectBlockedByCSRF bool
		description         string
	}{
		{
			name:                "matching_origin_passes",
			origin:              "https://app.example.com",
			expectBlockedByCSRF: false,
			description:         "Origin matching CORS policy should pass validation",
		},
		{
			name:                "non_matching_origin_blocked",
			origin:              "https://evil.com",
			expectBlockedByCSRF: true,
			description:         "Origin not in CORS policy should be blocked with 403",
		},
		{
			name:                "no_origin_passes",
			origin:              "",
			expectBlockedByCSRF: false,
			description:         "Missing Origin header should pass (backwards compatible)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a POST request to /auth/login
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
				httpSrv.URL+"/auth/login", strings.NewReader(`{"client_id":"test-client"}`))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			// The key check: origin validation should block with 403 only when
			// the origin doesn't match the CORS policy. Other status codes
			// indicate the request passed origin validation and proceeded.
			isBlockedByOrigin := (resp.StatusCode == http.StatusForbidden)
			if isBlockedByOrigin != tc.expectBlockedByCSRF {
				if tc.expectBlockedByCSRF {
					t.Errorf("%s: expected origin to be blocked with 403, got %d", tc.description, resp.StatusCode)
				} else {
					t.Errorf("%s: expected origin to pass validation, but got 403", tc.description)
				}
			}
		})
	}
}

// TestLogin_NoCORSPolicy_AllowsAllOrigins verifies that when no CORS policy
// is configured, all origins are allowed (backwards compatible behavior).
func TestLogin_NoCORSPolicy_AllowsAllOrigins(t *testing.T) {
	t.Parallel()

	users := defaultimpl.NewMemoryUserProvider()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "test-client", Secret: "test-secret", RedirectURIs: []string{"https://app.example.com/callback"},
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
		Active: true,
	})

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		// Note: No WithCORS() call
	)

	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	// Any origin should be allowed when no CORS policy is set
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		httpSrv.URL+"/auth/login", strings.NewReader(`{"client_id":"test-client"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://any-origin.com")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Should pass origin validation (fail later in flow with 400, not 403)
	if resp.StatusCode == http.StatusForbidden {
		t.Error("Expected origin validation to pass when no CORS policy is set")
	}
}

// TestLogin_WildcardCORS_AllowsAllOrigins verifies that wildcard CORS policy
// allows any origin.
func TestLogin_WildcardCORS_AllowsAllOrigins(t *testing.T) {
	t.Parallel()

	users := defaultimpl.NewMemoryUserProvider()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "test-client", Secret: "test-secret", RedirectURIs: []string{"https://app.example.com/callback"},
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
		Active: true,
	})

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithCORS(cors.Policy{
			AllowedOrigins: []string{"*"},
		}),
	)

	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	// Any origin should be allowed with wildcard
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		httpSrv.URL+"/auth/login", strings.NewReader(`{"client_id":"test-client"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://random-origin.com")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Should pass origin validation (fail later in flow with 400, not 403)
	if resp.StatusCode == http.StatusForbidden {
		t.Error("Expected origin validation to pass with wildcard CORS policy")
	}
}
