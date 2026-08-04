package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigBuildsTenantAndClientBindings(t *testing.T) {
	environment := validTestEnvironment(t)
	config, err := loadConfig(mapGetenv(environment))
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if config.TenantBindings["tenant-one"].BillingSecret != "billing-secret" {
		t.Fatal("billing secret was not resolved from its named environment variable")
	}
	if config.CheckoutBindings["checkout-client"].TenantID != "tenant-one" {
		t.Fatal("checkout client was not bound to tenant")
	}
}

func TestLoadConfigRejectsUnsafeDesiredStateFile(t *testing.T) {
	environment := validTestEnvironment(t)
	path := environment["SNAPLINK_STRIPE_BINDINGS_FILE"]
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(mapGetenv(environment)); !errors.Is(err, errInvalidConfig) {
		t.Fatalf("unsafe permissions error = %v", err)
	}

	target := writeBindingsFile(t, "bindings-target.json")
	link := filepath.Join(t.TempDir(), "bindings-link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	environment["SNAPLINK_STRIPE_BINDINGS_FILE"] = link
	if _, err := loadConfig(mapGetenv(environment)); !errors.Is(err, errInvalidConfig) {
		t.Fatalf("symlink error = %v", err)
	}
}

func TestLoadConfigRejectsInsecureRemoteService(t *testing.T) {
	environment := validTestEnvironment(t)
	environment["SNAPLINK_STRIPE_BILLING_BASE_URL"] = "http://billing.internal"
	if _, err := loadConfig(mapGetenv(environment)); !errors.Is(err, errInvalidConfig) {
		t.Fatalf("insecure service URL error = %v", err)
	}
}

func TestLoadConfigRejectsAmbiguousStripeEnvironment(t *testing.T) {
	tests := []struct {
		name, key, value string
	}{
		{name: "missing live mode", key: "SNAPLINK_STRIPE_LIVE_MODE", value: ""},
		{name: "live key in test mode", key: "SNAPLINK_STRIPE_API_KEY", value: "sk_live_value"},
		{name: "invalid account", key: "SNAPLINK_STRIPE_ACCOUNT", value: "connected"},
		{name: "invalid webhook version", key: "SNAPLINK_STRIPE_WEBHOOK_API_VERSION", value: "latest"},
		{name: "invalid webhook secret", key: "SNAPLINK_STRIPE_WEBHOOK_SECRETS", value: "shared-secret"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			environment := validTestEnvironment(t)
			environment[test.key] = test.value
			if _, err := loadConfig(mapGetenv(environment)); !errors.Is(err, errInvalidConfig) {
				t.Fatalf("configuration error = %v", err)
			}
		})
	}
}

func TestLoadConfigRejectsAmbiguousCheckoutClient(t *testing.T) {
	environment := validTestEnvironment(t)
	document := `{"version":1,"bindings":[` +
		`{"tenant_id":"tenant-one","checkout_client_ids":["shared"],"billing_client_id":"billing-one","billing_client_secret_env":"BILLING_SECRET"},` +
		`{"tenant_id":"tenant-two","checkout_client_ids":["shared"],"billing_client_id":"billing-two","billing_client_secret_env":"BILLING_SECRET"}]}`
	path := filepath.Join(t.TempDir(), "bindings.json")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	environment["SNAPLINK_STRIPE_BINDINGS_FILE"] = path
	if _, err := loadConfig(mapGetenv(environment)); !errors.Is(err, errInvalidConfig) {
		t.Fatalf("ambiguous client error = %v", err)
	}
}

func TestLoadConfigRejectsBillingClientSharedAcrossTenants(t *testing.T) {
	environment := validTestEnvironment(t)
	document := `{"version":1,"bindings":[` +
		`{"tenant_id":"tenant-one","checkout_client_ids":["checkout-one"],"billing_client_id":"shared-billing","billing_client_secret_env":"BILLING_SECRET"},` +
		`{"tenant_id":"tenant-two","checkout_client_ids":["checkout-two"],"billing_client_id":"shared-billing","billing_client_secret_env":"BILLING_SECRET"}]}`
	path := filepath.Join(t.TempDir(), "bindings.json")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	environment["SNAPLINK_STRIPE_BINDINGS_FILE"] = path
	if _, err := loadConfig(mapGetenv(environment)); !errors.Is(err, errInvalidConfig) {
		t.Fatalf("shared Billing client error = %v", err)
	}
}

func TestExecuteDoesNotLogDatabaseCredential(t *testing.T) {
	environment := validTestEnvironment(t)
	environment["SNAPLINK_STRIPE_POSTGRES_DSN"] = "postgres://adapter:must-not-leak@127.0.0.1:1/missing?sslmode=disable"
	var stderr bytes.Buffer
	if code := execute(context.Background(), &stderr, mapGetenv(environment)); code != 1 {
		t.Fatalf("execute() code = %d, stderr = %s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "must-not-leak") {
		t.Fatalf("database credential leaked: %s", stderr.String())
	}
}

func validTestEnvironment(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		"SNAPLINK_STRIPE_POSTGRES_DSN":            "postgres://stripe@localhost/stripe",
		"SNAPLINK_STRIPE_ISSUER":                  "http://127.0.0.1:18080",
		"SNAPLINK_STRIPE_JWKS_URL":                "http://127.0.0.1:18080/.well-known/jwks.json",
		"SNAPLINK_STRIPE_AUDIENCE":                "https://stripe-adapter.example.test",
		"SNAPLINK_STRIPE_BILLING_BASE_URL":        "http://127.0.0.1:18081",
		"SNAPLINK_STRIPE_TOKEN_URL":               "http://127.0.0.1:18080/token",
		"SNAPLINK_STRIPE_BILLING_RESOURCE":        "https://billing.example.test",
		"SNAPLINK_STRIPE_API_BASE_URL":            "http://127.0.0.1:18082",
		"SNAPLINK_STRIPE_API_VERSION":             "2025-06-30.basil",
		"SNAPLINK_STRIPE_WEBHOOK_API_VERSION":     "2025-06-30.basil",
		"SNAPLINK_STRIPE_LIVE_MODE":               "false",
		"SNAPLINK_STRIPE_ACCOUNT":                 "platform",
		"SNAPLINK_STRIPE_API_KEY":                 "sk_test_value",
		"SNAPLINK_STRIPE_WEBHOOK_SECRETS":         "whsec_old,whsec_new",
		"SNAPLINK_STRIPE_RETURN_ORIGINS":          "http://127.0.0.1:3000,https://console.example.test",
		"SNAPLINK_STRIPE_BINDINGS_FILE":           writeBindingsFile(t, "bindings.json"),
		"SNAPLINK_STRIPE_ALLOW_INSECURE_LOOPBACK": "true",
		"BILLING_SECRET":                          "billing-secret",
	}
}

func writeBindingsFile(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	document := `{"version":1,"bindings":[{"tenant_id":"tenant-one",` +
		`"checkout_client_ids":["checkout-client"],"billing_client_id":"billing-client",` +
		`"billing_client_secret_env":"BILLING_SECRET"}]}`
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mapGetenv(environment map[string]string) func(string) string {
	return func(key string) string { return environment[key] }
}
