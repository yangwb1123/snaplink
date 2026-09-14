package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

func publicRevokeDeps() (*revokeDeps, *memClientStore, *memRefreshStore) {
	clients := newMemClientStore()
	client := activeClient("public-client")
	client.TokenEndpointAuthMethod = "none"
	clients.put(client, "")
	refresh := newMemRefreshStore()
	return newRevokeDeps(clients, refresh), clients, refresh
}

func runRevokeRequest(d *revokeDeps, clientID, secret, token string) *httptest.ResponseRecorder {
	form := url.Values{"client_id": {clientID}, "token": {token}}
	if secret != "" {
		form.Set("client_secret", secret)
	}
	ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded, form.Encode())
	HandleRevoke(d, ctx)
	return rec
}

func TestPublicRevokeOwnAccessToken(t *testing.T) {
	d, _, _ := publicRevokeDeps()
	revokes := 0
	d.validate = func(context.Context, string) (*core.TokenClaims, string, error) {
		return &core.TokenClaims{TokenUse: core.TokenUseAccessToken, ClientID: "public-client"}, "jwt", nil
	}
	d.revokeAcross = func(context.Context, string) ([]string, []string) {
		revokes++
		return []string{"jwt"}, nil
	}
	if rec := runRevokeRequest(d, "public-client", "", "own-access"); rec.Code != http.StatusOK || revokes != 1 {
		t.Fatalf("revoke status=%d issuer calls=%d, want 200 and one revoke", rec.Code, revokes)
	}
}

func TestPublicRevokeOwnRefreshToken(t *testing.T) {
	d, _, refresh := publicRevokeDeps()
	if err := refresh.Issue(context.Background(), "own-refresh", &RefreshToken{
		UserID: "user", ClientID: "public-client", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if rec := runRevokeRequest(d, "public-client", "", "own-refresh"); rec.Code != http.StatusOK {
		t.Fatalf("revoke status=%d, want 200", rec.Code)
	}
	if _, err := refresh.Inspect(context.Background(), "own-refresh"); err == nil {
		t.Fatal("owned refresh token remains active")
	}
}

func TestPublicRevokeOtherClientAccessIsNoOp(t *testing.T) {
	d, _, _ := publicRevokeDeps()
	d.validate = func(context.Context, string) (*core.TokenClaims, string, error) {
		return &core.TokenClaims{TokenUse: core.TokenUseAccessToken, ClientID: "other-client"}, "jwt", nil
	}
	issuerCalls := 0
	d.revokeAcross = func(context.Context, string) ([]string, []string) {
		issuerCalls++
		return nil, nil
	}
	if rec := runRevokeRequest(d, "public-client", "", "other-access"); rec.Code != http.StatusOK || issuerCalls != 0 {
		t.Fatalf("revoke status=%d issuer calls=%d, want 200 and no mutation", rec.Code, issuerCalls)
	}
}

func TestPublicRevokeOtherClientRefreshIsNoOp(t *testing.T) {
	d, _, refresh := publicRevokeDeps()
	if err := refresh.Issue(context.Background(), "other-refresh", &RefreshToken{
		UserID: "user", ClientID: "other-client", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	issuerCalls := 0
	d.revokeAcross = func(context.Context, string) ([]string, []string) {
		issuerCalls++
		return nil, nil
	}
	if rec := runRevokeRequest(d, "public-client", "", "other-refresh"); rec.Code != http.StatusOK || issuerCalls != 0 {
		t.Fatalf("revoke status=%d issuer calls=%d, want 200 and no mutation", rec.Code, issuerCalls)
	}
	if _, err := refresh.Inspect(context.Background(), "other-refresh"); err != nil {
		t.Fatal("other client's refresh token was deleted")
	}
}

func TestPublicRevokeUnknownTokenIsNoOp(t *testing.T) {
	d, _, _ := publicRevokeDeps()
	issuerCalls := 0
	d.revokeAcross = func(context.Context, string) ([]string, []string) {
		issuerCalls++
		return nil, nil
	}
	if rec := runRevokeRequest(d, "public-client", "", "unknown-token"); rec.Code != http.StatusOK || issuerCalls != 0 {
		t.Fatalf("revoke status=%d issuer calls=%d, want 200 and no mutation", rec.Code, issuerCalls)
	}
}

func TestPublicRevokeRejectsClientSecretAuthentication(t *testing.T) {
	d, _, _ := publicRevokeDeps()
	if rec := runRevokeRequest(d, "public-client", "unexpected-secret", "own-access"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoke status=%d, want 401 for public client using a secret", rec.Code)
	}
}

func TestPublicClientCannotIntrospect(t *testing.T) {
	_, clients, refresh := publicRevokeDeps()
	introspect := newIntrospectDeps(clients, refresh)
	ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded, "token=own-access&client_id=public-client")
	HandleIntrospect(introspect, ctx)
	if rec.Code != http.StatusUnauthorized || decodeBody(t, rec)["error"] != core.ErrInvalidClient {
		t.Fatalf("introspection status=%d body=%s, want 401 invalid_client", rec.Code, rec.Body.String())
	}
}

func TestCredentialEndpointsRejectEmptyJSONAndDuplicateFormSecrets(t *testing.T) {
	for _, endpoint := range []string{"revoke", "introspect"} {
		for _, wire := range []struct{ name, contentType, body string }{
			{name: "duplicate form secret", contentType: ctFormURLEncoded,
				body: "token=opaque&client_id=confidential-client&client_secret=&client_secret=wrong"},
			{name: "empty JSON secret", contentType: "application/json",
				body: `{"token":"opaque","client_id":"confidential-client","client_secret":""}`},
		} {
			t.Run(endpoint+"/"+wire.name, func(t *testing.T) {
				clients := newMemClientStore()
				client := activeClient("confidential-client")
				client.TokenEndpointAuthMethod = "client_secret_basic"
				clients.put(client, "secret")
				ctx, rec := newCtx(http.MethodPost, wire.contentType, wire.body)
				ctx.Request().SetBasicAuth(client.ID, "secret")
				if endpoint == "revoke" {
					HandleRevoke(newRevokeDeps(clients, newMemRefreshStore()), ctx)
				} else {
					HandleIntrospect(newIntrospectDeps(clients, newMemRefreshStore()), ctx)
				}
				if rec.Code != http.StatusUnauthorized {
					t.Fatalf("status=%d body=%s, want 401 for mixed Basic + present-empty body secret", rec.Code, rec.Body.String())
				}
			})
		}
	}
}

func TestCredentialAssertionsRejectPresentEmptySecret(t *testing.T) {
	for _, endpoint := range []string{"revoke", "introspect"} {
		for _, wire := range []struct{ name, contentType, body string }{
			{name: "form", contentType: ctFormURLEncoded,
				body: "token=opaque&client_id=confidential-client&client_secret=&client_assertion=assertion&client_assertion_type=" + ClientAssertionTypeJWTBearer},
			{name: "JSON", contentType: "application/json",
				body: `{"token":"opaque","client_id":"confidential-client","client_secret":"","client_assertion":"assertion","client_assertion_type":"` + ClientAssertionTypeJWTBearer + `"}`},
		} {
			t.Run(endpoint+"/"+wire.name, func(t *testing.T) {
				clients := newMemClientStore()
				client := activeClient("confidential-client")
				client.TokenEndpointAuthMethod = "private_key_jwt"
				clients.put(client, "secret")
				ctx, rec := newCtx(http.MethodPost, wire.contentType, wire.body)
				if endpoint == "revoke" {
					deps := newRevokeDeps(clients, newMemRefreshStore())
					deps.verifyCA = func(context.Context, string, string, string) (string, error) { return client.ID, nil }
					HandleRevoke(deps, ctx)
				} else {
					deps := newIntrospectDeps(clients, newMemRefreshStore())
					deps.verifyCA = func(context.Context, string, string, string) (string, error) { return client.ID, nil }
					HandleIntrospect(deps, ctx)
				}
				if rec.Code != http.StatusUnauthorized {
					t.Fatalf("status=%d body=%s, want 401 for assertion + present-empty client_secret", rec.Code, rec.Body.String())
				}
			})
		}
	}
}

func TestIntrospectionEnforcesRegisteredClientAuthMethod(t *testing.T) {
	cases := []struct {
		name, method string
		basic        bool
		bodySecret   bool
		assertion    bool
		want         int
	}{
		{name: "Basic rejects post credentials", method: "client_secret_basic", bodySecret: true, want: http.StatusUnauthorized},
		{name: "post rejects Basic credentials", method: "client_secret_post", basic: true, want: http.StatusUnauthorized},
		{name: "post rejects assertion authentication", method: "client_secret_post", assertion: true, want: http.StatusUnauthorized},
		{name: "private key rejects secret downgrade", method: "private_key_jwt", bodySecret: true, want: http.StatusUnauthorized},
		{name: "tls rejects secret downgrade", method: "tls_client_auth", bodySecret: true, want: http.StatusUnauthorized},
		{name: "self signed tls rejects secret downgrade", method: "self_signed_tls", bodySecret: true, want: http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clients := newMemClientStore()
			client := activeClient("confidential-client")
			client.TokenEndpointAuthMethod = tc.method
			clients.put(client, "secret")
			form := url.Values{"token": {"opaque"}, "client_id": {client.ID}}
			if tc.bodySecret {
				form.Set("client_secret", "secret")
			}
			deps := newIntrospectDeps(clients, newMemRefreshStore())
			if tc.assertion {
				form.Set("client_assertion", "assertion")
				form.Set("client_assertion_type", ClientAssertionTypeJWTBearer)
				deps.verifyCA = func(context.Context, string, string, string) (string, error) { return client.ID, nil }
			}
			ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded, form.Encode())
			if tc.basic {
				ctx.Request().SetBasicAuth(client.ID, "secret")
			}
			HandleIntrospect(deps, ctx)
			if rec.Code != tc.want {
				t.Fatalf("status=%d, want %d", rec.Code, tc.want)
			}
		})
	}
}

func TestConfidentialRevokeOtherClientIsNoOp(t *testing.T) {
	clients := newMemClientStore()
	clients.put(activePostClient("confidential-client"), "secret")
	d := newRevokeDeps(clients, newMemRefreshStore())
	d.validate = func(context.Context, string) (*core.TokenClaims, string, error) {
		return &core.TokenClaims{TokenUse: core.TokenUseAccessToken, ClientID: "other-client"}, "jwt", nil
	}
	issuerCalls := 0
	d.revokeAcross = func(context.Context, string) ([]string, []string) {
		issuerCalls++
		return nil, nil
	}
	if rec := runRevokeRequest(d, "confidential-client", "secret", "other-access"); rec.Code != http.StatusOK || issuerCalls != 0 {
		t.Fatalf("revoke status=%d issuer calls=%d, want 200 and no mutation", rec.Code, issuerCalls)
	}
}

func TestConfidentialRevokeOwnAccessToken(t *testing.T) {
	clients := newMemClientStore()
	clients.put(activePostClient("confidential-client"), "secret")
	d := newRevokeDeps(clients, newMemRefreshStore())
	d.validate = func(context.Context, string) (*core.TokenClaims, string, error) {
		return &core.TokenClaims{TokenUse: core.TokenUseAccessToken, ClientID: "confidential-client"}, "jwt", nil
	}
	revokes := 0
	d.revokeAcross = func(context.Context, string) ([]string, []string) {
		revokes++
		return []string{"jwt"}, nil
	}
	if rec := runRevokeRequest(d, "confidential-client", "secret", "own-access"); rec.Code != http.StatusOK || revokes != 1 {
		t.Fatalf("revoke status=%d issuer calls=%d, want 200 and one revoke", rec.Code, revokes)
	}
}

func TestRevokeValidationRejectionAndBackendErrorsDiffer(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{name: "malformed or expired token", err: core.ErrTokenValidationRejected, want: http.StatusOK},
		{name: "issuer backend outage", err: errors.New("issuer store unavailable"), want: http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _, _ := publicRevokeDeps()
			d.validate = func(context.Context, string) (*core.TokenClaims, string, error) {
				return nil, "", tc.err
			}
			rec := runRevokeRequest(d, "public-client", "", "unknown-or-invalid")
			if rec.Code != tc.want {
				t.Fatalf("status=%d, want %d", rec.Code, tc.want)
			}
			if tc.want == http.StatusServiceUnavailable && rec.Header().Get(core.HeaderRetryAfter) != "1" {
				t.Fatalf("retry-after=%q, want 1", rec.Header().Get(core.HeaderRetryAfter))
			}
		})
	}
}

func TestRevokeEnforcesRegisteredClientAuthMethod(t *testing.T) {
	cases := []struct {
		name   string
		method string
		basic  bool
		want   int
	}{
		{name: "basic rejects post credentials", method: "client_secret_basic", want: http.StatusUnauthorized},
		{name: "post rejects basic credentials", method: "client_secret_post", basic: true, want: http.StatusUnauthorized},
		{name: "private key jwt rejects secret downgrade", method: "private_key_jwt", want: http.StatusUnauthorized},
		{name: "tls rejects secret downgrade", method: "tls_client_auth", want: http.StatusUnauthorized},
		{name: "self signed tls rejects secret downgrade", method: "self_signed_tls", want: http.StatusUnauthorized},
		{name: "registered default basic rejects post", method: "", want: http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clients := newMemClientStore()
			client := activeClient("confidential-client")
			client.TokenEndpointAuthMethod = tc.method
			clients.put(client, "secret")
			d := newRevokeDeps(clients, newMemRefreshStore())
			ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded, "token=t&client_id=confidential-client&client_secret=secret")
			if tc.basic {
				ctx.Request().SetBasicAuth("confidential-client", "secret")
			}
			HandleRevoke(d, ctx)
			if rec.Code != tc.want {
				t.Fatalf("status=%d, want %d", rec.Code, tc.want)
			}
		})
	}
}

func TestPublicRevokeDeletesRefreshFamily(t *testing.T) {
	d, _, base := publicRevokeDeps()
	refresh := &familyRefreshTestStore{memRefreshStore: base}
	d.refresh = refresh
	ctx := context.Background()
	for _, token := range []string{"refresh-current", "refresh-sibling", "refresh-other"} {
		family := "login-family"
		if token == "refresh-other" {
			family = "another-login"
		}
		if err := refresh.Issue(ctx, token, &RefreshToken{
			UserID: "user", ClientID: "public-client", FamilyID: family, ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if rec := runRevokeRequest(d, "public-client", "", "refresh-current"); rec.Code != http.StatusOK {
		t.Fatalf("revoke status=%d, want 200", rec.Code)
	}
	for _, token := range []string{"refresh-current", "refresh-sibling"} {
		if _, err := refresh.Inspect(ctx, token); err == nil {
			t.Errorf("same-family token %q remains active", token)
		}
	}
	if _, err := refresh.Inspect(ctx, "refresh-other"); err != nil {
		t.Fatal("different login family was revoked")
	}
}

type familyRefreshTestStore struct {
	*memRefreshStore
}

func (s *familyRefreshTestStore) DeleteFamily(_ context.Context, familyID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	deleted := 0
	for token, info := range s.entries {
		if info.FamilyID == familyID {
			delete(s.entries, token)
			deleted++
		}
	}
	return deleted, nil
}

func TestRevokeBackendFailureReturnsRetryable503(t *testing.T) {
	d, _, _ := publicRevokeDeps()
	d.validate = func(context.Context, string) (*core.TokenClaims, string, error) {
		return &core.TokenClaims{TokenUse: core.TokenUseAccessToken, ClientID: "public-client"}, "jwt", nil
	}
	d.revokeAcross = func(context.Context, string) ([]string, []string) {
		return nil, []string{"jwt"}
	}
	rec := runRevokeRequest(d, "public-client", "", "own-access")
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get(core.HeaderRetryAfter) != "1" {
		t.Fatalf("status=%d retry-after=%q, want retryable 503", rec.Code, rec.Header().Get(core.HeaderRetryAfter))
	}
}

type failingFamilyRefreshStore struct {
	*memRefreshStore
}

func (s *failingFamilyRefreshStore) DeleteFamily(context.Context, string) (int, error) {
	return 0, errTestInvalidToken
}

func TestRefreshFamilyFailureReturnsRetryable503(t *testing.T) {
	clients := newMemClientStore()
	client := activeClient("public-client")
	client.TokenEndpointAuthMethod = "none"
	clients.put(client, "")
	base := newMemRefreshStore()
	ctx := context.Background()
	if err := base.Issue(ctx, "family-refresh", &RefreshToken{
		UserID: "user", ClientID: "public-client", FamilyID: "family", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	d := newRevokeDeps(clients, &failingFamilyRefreshStore{memRefreshStore: base})
	rec := runRevokeRequest(d, "public-client", "", "family-refresh")
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get(core.HeaderRetryAfter) != "1" {
		t.Fatalf("status=%d retry-after=%q, want retryable 503", rec.Code, rec.Header().Get(core.HeaderRetryAfter))
	}
	if _, err := base.Inspect(ctx, "family-refresh"); err != nil {
		t.Fatal("failed family deletion unexpectedly removed token")
	}
}

type failingInspectRefreshStore struct {
	*memRefreshStore
}

func (s *failingInspectRefreshStore) Inspect(context.Context, string) (*RefreshToken, error) {
	return nil, errTestInvalidToken
}

func TestRefreshInspectionFailureReturnsRetryable503(t *testing.T) {
	clients := newMemClientStore()
	client := activeClient("public-client")
	client.TokenEndpointAuthMethod = "none"
	clients.put(client, "")
	d := newRevokeDeps(clients, &failingInspectRefreshStore{memRefreshStore: newMemRefreshStore()})
	rec := runRevokeRequest(d, "public-client", "", "unknown-or-refresh")
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get(core.HeaderRetryAfter) != "1" {
		t.Fatalf("status=%d retry-after=%q, want retryable 503", rec.Code, rec.Header().Get(core.HeaderRetryAfter))
	}
}
