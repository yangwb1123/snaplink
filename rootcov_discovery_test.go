package sso_test

// rootcov_discovery_test.go exercises the discovery document, JWKS, the
// operational probes, and the device / PAR / DCR / password-reset grant
// endpoints over HTTP so discovery_config.go, discovery_cache.go,
// oidc_configuration.go, device_code_handler.go, handle_par/register, and
// handle_password_reset.go get covered. Reuses rcov* helpers.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/oauth"
)

// rcovGetJSON GETs a URL and decodes the JSON body.
func rcovGetJSON(t *testing.T, url string, v any) *http.Response {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if v != nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, v)
	}
	return resp
}

// TestRcovDisc_DiscoveryDoc fetches the OIDC discovery document twice so the
// snapshot + body cache + ETag (304) machinery is covered.
func TestRcovDisc_DiscoveryDoc(t *testing.T) {
	s := rcovNewServer(t, sso.WithDiscoveryCacheTTL(5*time.Second), sso.WithDiscoveryDocCacheTTL(5*time.Second))

	var doc map[string]any
	resp := rcovGetJSON(t, s.http.URL+"/.well-known/openid-configuration", &doc)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status=%d", resp.StatusCode)
	}
	if doc["issuer"] == nil {
		t.Errorf("discovery missing issuer: %v", doc)
	}
	etag := resp.Header.Get("ETag")

	// Second fetch warms / serves from the body cache.
	resp2 := rcovGetJSON(t, s.http.URL+"/.well-known/openid-configuration", nil)
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("discovery 2 status=%d", resp2.StatusCode)
	}

	// Conditional request with the ETag => 304 when caching is enabled.
	if etag != "" {
		req, _ := http.NewRequest(http.MethodGet, s.http.URL+"/.well-known/openid-configuration", nil)
		req.Header.Set("If-None-Match", etag)
		resp3, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("conditional discovery: %v", err)
		}
		_ = resp3.Body.Close()
		if resp3.StatusCode != http.StatusNotModified && resp3.StatusCode != http.StatusOK {
			t.Errorf("conditional discovery status=%d, want 304 or 200", resp3.StatusCode)
		}
	}
}

// TestRcovDisc_JWKS fetches the JWKS twice to cover the single-flight body cache.
func TestRcovDisc_JWKS(t *testing.T) {
	s := rcovNewServer(t)
	for i := 0; i < 2; i++ {
		var body map[string]any
		resp := rcovGetJSON(t, s.http.URL+"/.well-known/jwks.json", &body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("jwks status=%d", resp.StatusCode)
		}
		if _, ok := body["keys"]; !ok {
			t.Errorf("jwks missing keys: %v", body)
		}
	}
}

// TestRcovDisc_Probes hits the operational probes registered outside middleware.
func TestRcovDisc_Probes(t *testing.T) {
	s := rcovNewServer(t)
	for _, path := range []string{"/livez", "/readyz", "/health"} {
		resp := rcovGetJSON(t, s.http.URL+path, nil)
		if resp.StatusCode >= 500 {
			t.Errorf("GET %s = %d, want < 500", path, resp.StatusCode)
		}
	}
}

// TestRcovDisc_DeviceCode covers the device-authorization endpoint when a
// device-code store is wired.
func TestRcovDisc_DeviceCode(t *testing.T) {
	s := rcovNewServer(t, sso.WithDeviceCodeStore(
		defaultimpl.NewMemoryDeviceCodeStore(), 5*time.Minute, 5*time.Second, "https://opt.example.com/device"))

	status, out := rcovPostJSON(t, s.http.URL+"/device/code", "", map[string]any{
		"client_id": rcovClient,
		"scope":     "openid",
	})
	if status != http.StatusOK {
		t.Fatalf("device/code status=%d body=%v", status, out)
	}
	if out["device_code"] == "" || out["user_code"] == "" {
		t.Errorf("device response missing codes: %v", out)
	}
}

// TestRcovDisc_PAR covers the pushed-authorization-request endpoint.
func TestRcovDisc_PAR(t *testing.T) {
	s := rcovNewServer(t, sso.WithPARStore(defaultimpl.NewMemoryPARStore(), time.Minute))

	status, out := rcovPostJSON(t, s.http.URL+"/par", "", map[string]any{
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
		"response_type": "code",
		"redirect_uri":  rcovRedirect,
		"scope":         "openid",
	})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("par status=%d body=%v", status, out)
	}
	if out["request_uri"] == "" || out["request_uri"] == nil {
		t.Errorf("PAR response missing request_uri: %v", out)
	}
}

// TestRcovDisc_DCR covers dynamic client registration (open registration).
func TestRcovDisc_DCR(t *testing.T) {
	s := rcovNewServer(t, sso.WithDynamicClientRegistration(oauth.DCRPolicy{
		AllowOpenRegistration: true,
		DefaultActive:         true,
	}))

	status, out := rcovPostJSON(t, s.http.URL+"/register", "", map[string]any{
		"client_name":   "Dynamically Registered",
		"redirect_uris": []string{"https://dyn.example.com/cb"},
	})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("register status=%d body=%v", status, out)
	}
	clientID, _ := out["client_id"].(string)
	if clientID == "" {
		t.Fatalf("DCR response missing client_id: %v", out)
	}

	// GET /register/:id requires the registration access token; without it the
	// anti-enumeration contract returns an identical 401.
	status, _ = rcovDo(t, http.MethodGet, s.http.URL+"/register/"+clientID, "", nil)
	if status != http.StatusUnauthorized {
		t.Errorf("unauth register GET = %d, want 401", status)
	}
}

// rcovResetSender is a no-op PasswordResetSender capturing the last token.
type rcovResetSender struct{ lastToken string }

func (r *rcovResetSender) SendResetToken(_ context.Context, _, token string) error {
	r.lastToken = token
	return nil
}

// TestRcovDisc_PasswordReset covers POST /auth/forgot-password (anti-enumeration
// 200) and POST /auth/reset-password (oracle-safe consume).
func TestRcovDisc_PasswordReset(t *testing.T) {
	sender := &rcovResetSender{}
	s := rcovNewServer(t,
		sso.WithPasswordResetStore(defaultimpl.NewMemoryPasswordResetStore(), time.Hour),
		sso.WithPasswordResetResolver(func(_ context.Context, id string) (string, error) {
			if id == "alice@example.com" {
				return rcovUser, nil
			}
			return "", nil
		}),
		sso.WithPasswordResetDeliveryResolver(func(_ context.Context, _ string) (string, error) {
			return "alice@example.com", nil
		}),
		sso.WithPasswordResetSender(sender),
	)

	// Known identifier => 200 sent, token delivered to the sender.
	status, out := rcovPostJSON(t, s.http.URL+"/auth/forgot-password", "", map[string]any{
		"identifier": "alice@example.com",
	})
	if status != http.StatusOK || out["status"] != "sent" {
		t.Fatalf("forgot-password = %d %v, want 200 sent", status, out)
	}
	if sender.lastToken == "" {
		t.Fatalf("reset token not delivered")
	}

	// Unknown identifier => still 200 (anti-enumeration).
	status, out = rcovPostJSON(t, s.http.URL+"/auth/forgot-password", "", map[string]any{
		"identifier": "nobody@example.com",
	})
	if status != http.StatusOK {
		t.Errorf("forgot-password unknown = %d, want 200 (anti-enumeration)", status)
	}

	// Reset with the delivered token => 200/204.
	status, _ = rcovPostJSON(t, s.http.URL+"/auth/reset-password", "", map[string]any{
		"token":        sender.lastToken,
		"new_password": "fresh-password",
	})
	if status != http.StatusOK && status != http.StatusNoContent {
		t.Errorf("reset-password = %d, want 200/204", status)
	}

	// Replaying the consumed token => 400 reset_invalid (oracle-safe).
	status, out = rcovPostJSON(t, s.http.URL+"/auth/reset-password", "", map[string]any{
		"token":        sender.lastToken,
		"new_password": "another-one",
	})
	if status != http.StatusBadRequest {
		t.Errorf("reset replay = %d, want 400 (body=%v)", status, out)
	}
}
