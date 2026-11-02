package rs_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
)

// revocationFixture exercises genuine JWT/JWKS HTTP validation or the existing
// authenticated introspection fixture. A nil override removes a claim.
func revocationFixture(t *testing.T, mode string, overrides map[string]any) (string, rs.Config) {
	t.Helper()
	cfg := rs.Config{Issuer: "https://as.test", ExpectedAud: "api://orders"}
	var mint func(map[string]any) (string, error)
	if mode == "local" {
		iss := newTestIssuer(t)
		cfg = newTestConfig(t, iss, "api://orders")
		mint = iss.MintAccessToken
	}
	cfg.AllowedServingRegions = []string{"eu-west-1"}
	values := map[string]any{
		"active": true, "iss": cfg.Issuer, "sub": "user-1",
		"aud": "api://orders", "client_id": "client-1", "tenant_id": "tenant-1",
		"jti": "token-1", "serving_region": "eu-west-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	for key, value := range overrides {
		if value == nil {
			delete(values, key)
		} else {
			values[key] = value
		}
	}
	if mint != nil {
		token, err := mint(values)
		if err != nil {
			t.Fatal(err)
		}
		return token, cfg
	}
	srv := introspectServer(t, "rs-client", "rs-secret", values)
	cfg.IntrospectURL = srv.URL
	cfg.IntrospectCreds = &rs.ClientCreds{ID: "rs-client", Secret: "rs-secret"}
	return "opaque-token", cfg
}

func validateRevocationFixture(ctx context.Context, token string, cfg rs.Config) (*rs.Claims, error) {
	if cfg.IntrospectURL != "" {
		return rs.ValidateTokenWithIntrospect(ctx, token, cfg)
	}
	return rs.ValidateToken(ctx, token, cfg)
}

func TestRevocationCheck_Verdicts(t *testing.T) {
	t.Parallel()
	backendErr := errors.New("private backend connection/namespace details")
	cases := []struct {
		name      string
		overrides map[string]any
		enabled   bool
		revoked   bool
		err       error
		wantCalls int
		inactive  bool
	}{
		{name: "allowed", enabled: true, wantCalls: 1},
		{name: "revoked", enabled: true, revoked: true, wantCalls: 1, inactive: true},
		{name: "backend_error", enabled: true, err: backendErr, wantCalls: 1, inactive: true},
		{name: "revoked_and_error", enabled: true, revoked: true, err: backendErr, wantCalls: 1, inactive: true},
		{name: "missing_jti", overrides: map[string]any{"jti": nil}, enabled: true, inactive: true},
		{name: "empty_jti", overrides: map[string]any{"jti": ""}, enabled: true, inactive: true},
		{name: "nil_hook"},
		{name: "nil_hook_missing_jti", overrides: map[string]any{"jti": nil}},
	}
	for _, mode := range []string{"local", "introspection"} {
		for _, tc := range cases {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				token, cfg := revocationFixture(t, mode, tc.overrides)
				calls := 0
				if tc.enabled {
					cfg.RevocationCheck = func(context.Context, rs.RevocationToken) (bool, error) {
						calls++
						return tc.revoked, tc.err
					}
				}
				claims, err := validateRevocationFixture(context.Background(), token, cfg)
				if calls != tc.wantCalls {
					t.Errorf("callback calls = %d, want %d", calls, tc.wantCalls)
				}
				if tc.inactive {
					if claims != nil || err != rs.ErrTokenInactive {
						t.Fatalf("claims present=%v, err=%v; want nil/ErrTokenInactive without backend details", claims != nil, err)
					}
				} else if claims == nil || err != nil {
					t.Fatalf("claims present=%v, err=%v; want valid token", claims != nil, err)
				}
			})
		}
	}
}

func TestRevocationCheck_ValueDescriptor(t *testing.T) {
	t.Parallel()
	typ := reflect.TypeOf(rs.RevocationToken{})
	if typ.NumField() != 4 {
		t.Fatalf("RevocationToken has %d fields, want only four namespace strings", typ.NumField())
	}
	for i := 0; i < typ.NumField(); i++ {
		if field := typ.Field(i); field.Type.Kind() != reflect.String {
			t.Errorf("RevocationToken.%s is %v, want immutable string", field.Name, field.Type)
		}
	}
	for _, mode := range []string{"local", "introspection"} {
		t.Run(mode, func(t *testing.T) {
			token, cfg := revocationFixture(t, mode, nil)
			before, err := validateRevocationFixture(context.Background(), token, cfg)
			if err != nil {
				t.Fatal(err)
			}
			want := rs.RevocationToken{Issuer: cfg.Issuer, TenantID: "tenant-1", ClientID: "client-1", JTI: "token-1"}
			calls := 0
			cfg.RevocationCheck = func(_ context.Context, got rs.RevocationToken) (bool, error) {
				calls++
				if got != want {
					t.Errorf("namespace = %+v, want %+v", got, want)
				}
				got.Issuer, got.TenantID, got.ClientID, got.JTI = "changed", "changed", "changed", "changed"
				return false, nil
			}
			after, err := validateRevocationFixture(context.Background(), token, cfg)
			if err != nil || calls != 1 || !reflect.DeepEqual(after, before) {
				t.Fatalf("callback mutated validated claims: calls=%d, err=%v, before=%+v, after=%+v", calls, err, before, after)
			}
		})
	}
}

func TestRevocationCheck_IntrospectionOptionalNamespace(t *testing.T) {
	t.Parallel()
	token, cfg := revocationFixture(t, "introspection", map[string]any{
		"iss": nil, "tenant_id": nil, "client_id": nil, "exp": nil,
	})
	calls := 0
	cfg.RevocationCheck = func(_ context.Context, got rs.RevocationToken) (bool, error) {
		calls++
		want := rs.RevocationToken{Issuer: cfg.Issuer, JTI: "token-1"}
		if got != want {
			t.Errorf("namespace = %+v, want configured issuer and empty optional fields %+v", got, want)
		}
		return false, nil
	}
	claims, err := validateRevocationFixture(context.Background(), token, cfg)
	if err != nil || claims == nil || calls != 1 {
		t.Fatalf("claims present=%v, err=%v, calls=%d", claims != nil, err, calls)
	}
	if claims.Issuer != "" || claims.TenantID != "" || claims.ClientID != "" || claims.ExpiresAt != 0 {
		t.Errorf("optional introspection claims were rewritten: %+v", claims)
	}
	for _, name := range []string{"iss", "tenant_id", "client_id", "exp"} {
		if _, exists := claims.Raw[name]; exists {
			t.Errorf("optional field %s was inserted into Raw", name)
		}
	}
}

func TestRevocationCheck_RejectsRevoked(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"local", "introspection"} {
		t.Run(mode, func(t *testing.T) {
			token, cfg := revocationFixture(t, mode, nil)
			calls := 0
			cfg.RevocationCheck = func(context.Context, rs.RevocationToken) (bool, error) {
				calls++
				return true, nil
			}
			claims, err := validateRevocationFixture(context.Background(), token, cfg)
			if calls != 1 {
				t.Errorf("revocation callback calls = %d, want 1", calls)
			}
			if claims != nil || !errors.Is(err, rs.ErrTokenInactive) {
				t.Errorf("revoked token admitted: claims present=%v, err=%v; want nil/ErrTokenInactive", claims != nil, err)
			}
		})
	}
}
