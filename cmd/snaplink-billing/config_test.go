package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseRuntimeConfigRequiresExplicitDevMemory(t *testing.T) {
	environment := map[string]string{
		"SNAPLINK_BILLING_ISSUER":               "https://sso.example",
		"SNAPLINK_BILLING_AUDIENCE":             "https://billing.example",
		"SNAPLINK_BILLING_POSTGRES_DSN":         "postgres://billing@db/billing",
		"SNAPLINK_BILLING_SOURCE_BINDINGS_FILE": " /run/config/source-bindings.json ",
	}
	config, err := parseRuntimeConfig(nil, mapEnvironment(environment), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if config.DevMemory || config.Postgres.DSN == "" ||
		config.SourceBindingsFile != "/run/config/source-bindings.json" {
		t.Fatalf("config = %+v", config)
	}
	delete(environment, "SNAPLINK_BILLING_POSTGRES_DSN")
	if _, err := parseRuntimeConfig(nil, mapEnvironment(environment), &bytes.Buffer{}); err == nil {
		t.Fatal("production config without PostgreSQL was accepted")
	}
}

func TestParseRuntimeConfigDevMemoryIsLoopbackOnly(t *testing.T) {
	args := []string{
		"--dev-memory", "--listen", "127.0.0.1:0", "--issuer", "http://127.0.0.1:8080",
		"--audience", "billing-api", "--allow-insecure-loopback",
	}
	config, err := parseRuntimeConfig(args, mapEnvironment(nil), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if config.JWKSURL != "http://127.0.0.1:8080/.well-known/jwks.json" {
		t.Fatalf("JWKS URL = %q", config.JWKSURL)
	}
	args[2] = "0.0.0.0:8080"
	if _, err := parseRuntimeConfig(args, mapEnvironment(nil), &bytes.Buffer{}); err == nil {
		t.Fatal("non-loopback dev-memory listen was accepted")
	}
}

func TestParseRuntimeConfigProductionAlsoRequiresLoopbackEdge(t *testing.T) {
	environment := map[string]string{
		"SNAPLINK_BILLING_LISTEN":       "0.0.0.0:8090",
		"SNAPLINK_BILLING_ISSUER":       "https://sso.example",
		"SNAPLINK_BILLING_AUDIENCE":     "billing-api",
		"SNAPLINK_BILLING_POSTGRES_DSN": "postgres://billing@db/billing",
	}
	if _, err := parseRuntimeConfig(nil, mapEnvironment(environment), &bytes.Buffer{}); err == nil {
		t.Fatal("plaintext non-loopback production listener was accepted")
	}
}

func TestParseRuntimeConfigAuditSecretsAreEnvironmentOnly(t *testing.T) {
	secret := "not-for-argv"
	environment := map[string]string{
		"SNAPLINK_BILLING_DEV_MEMORY":          "true",
		"SNAPLINK_BILLING_ISSUER":              "https://sso.example",
		"SNAPLINK_BILLING_AUDIENCE":            "billing-api",
		"SNAPLINK_BILLING_AUDIT_BASE_URL":      "https://audit.example",
		"SNAPLINK_BILLING_AUDIT_CLIENT_ID":     "snaplink-relay",
		"SNAPLINK_BILLING_AUDIT_CLIENT_SECRET": secret,
	}
	config, err := parseRuntimeConfig(nil, mapEnvironment(environment), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if config.Audit.ClientSecret != secret || config.Audit.TokenURL != "https://sso.example/token" {
		t.Fatalf("audit config was not resolved: %+v", config.Audit)
	}
	environment["SNAPLINK_BILLING_AUDIT_SCOPE"] = "audit:event:write admin:write"
	if _, err := parseRuntimeConfig(nil, mapEnvironment(environment), &bytes.Buffer{}); err == nil {
		t.Fatal("over-privileged audit relay scope was accepted")
	}
	delete(environment, "SNAPLINK_BILLING_AUDIT_SCOPE")
	delete(environment, "SNAPLINK_BILLING_AUDIT_BASE_URL")
	_, err = parseRuntimeConfig(nil, mapEnvironment(environment), &bytes.Buffer{})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("partial audit config error = %v", err)
	}
}

func TestParseRuntimeConfigAuditRuntimeFileNeedsConfiguredRelay(t *testing.T) {
	environment := map[string]string{
		"SNAPLINK_BILLING_DEV_MEMORY":         "true",
		"SNAPLINK_BILLING_ISSUER":             "https://sso.example",
		"SNAPLINK_BILLING_AUDIENCE":           "billing-api",
		"SNAPLINK_BILLING_AUDIT_RUNTIME_FILE": "/run/config/audit-runtime.json",
	}
	if _, err := parseRuntimeConfig(nil, mapEnvironment(environment), &bytes.Buffer{}); err == nil {
		t.Fatal("runtime desired state without a configured relay was accepted")
	}
}

func TestParseRuntimeConfigAuditSourcePrefixMigration(t *testing.T) {
	base := map[string]string{
		"SNAPLINK_BILLING_DEV_MEMORY": "true", "SNAPLINK_BILLING_ISSUER": "https://sso.example",
		"SNAPLINK_BILLING_AUDIENCE": "billing-api",
	}
	base["SNAPLINK_BILLING_AUDIT_SOURCE_SYSTEM"] = "legacy-commerce"
	config, err := parseRuntimeConfig(nil, mapEnvironment(base), &bytes.Buffer{})
	if err != nil || config.Audit.SourcePrefix != "legacy-commerce" {
		t.Fatalf("legacy prefix migration = %q, %v", config.Audit.SourcePrefix, err)
	}
	base["SNAPLINK_BILLING_AUDIT_SOURCE_PREFIX"] = "new-commerce"
	if _, err := parseRuntimeConfig(nil, mapEnvironment(base), &bytes.Buffer{}); err == nil {
		t.Fatal("conflicting source prefix and legacy source system were accepted")
	}
}

func TestParseRuntimeConfigRejectsUnsafeUpstreams(t *testing.T) {
	environment := map[string]string{
		"SNAPLINK_BILLING_DEV_MEMORY": "true",
		"SNAPLINK_BILLING_ISSUER":     "http://sso.example",
		"SNAPLINK_BILLING_AUDIENCE":   "billing-api",
	}
	if _, err := parseRuntimeConfig(nil, mapEnvironment(environment), &bytes.Buffer{}); err == nil {
		t.Fatal("non-loopback HTTP issuer was accepted")
	}
	environment["SNAPLINK_BILLING_ISSUER"] = "http://localhost:8080"
	environment["SNAPLINK_BILLING_ALLOW_INSECURE_LOOPBACK"] = "true"
	if _, err := parseRuntimeConfig(nil, mapEnvironment(environment), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
}

func TestParseRuntimeConfigPreservesExactIssuer(t *testing.T) {
	environment := map[string]string{
		"SNAPLINK_BILLING_DEV_MEMORY": "true",
		"SNAPLINK_BILLING_ISSUER":     "https://sso.example/tenant/",
		"SNAPLINK_BILLING_AUDIENCE":   "billing-api",
	}
	config, err := parseRuntimeConfig(nil, mapEnvironment(environment), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if config.Issuer != environment["SNAPLINK_BILLING_ISSUER"] ||
		config.JWKSURL != "https://sso.example/tenant/.well-known/jwks.json" {
		t.Fatalf("issuer=%q jwks=%q", config.Issuer, config.JWKSURL)
	}
}

func TestParseRuntimeConfigQuotaRelayIsLeastPrivilegeAndEnvironmentOnly(t *testing.T) {
	secret := "quota-secret-not-for-argv"
	environment := map[string]string{
		"SNAPLINK_BILLING_DEV_MEMORY": "true", "SNAPLINK_BILLING_ISSUER": "https://sso.example",
		"SNAPLINK_BILLING_AUDIENCE": "billing-api", "SNAPLINK_BILLING_QUOTA_BASE_URL": "https://sso.example",
		"SNAPLINK_BILLING_QUOTA_CLIENT_ID":     "billing-quota-relay",
		"SNAPLINK_BILLING_QUOTA_CLIENT_SECRET": secret,
		"SNAPLINK_BILLING_QUOTA_RESOURCE":      "sso-quota-api",
	}
	config, err := parseRuntimeConfig(nil, mapEnvironment(environment), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if config.Quota.ClientSecret != secret || config.Quota.TokenURL != "https://sso.example/token" ||
		config.Quota.Scope != "tenant-quota:projection:write" ||
		config.Quota.SourcePrefix != defaultQuotaSourcePrefix || config.Quota.RelayOwner == "" {
		t.Fatalf("quota config = %+v", config.Quota)
	}
	environment["SNAPLINK_BILLING_QUOTA_SCOPE"] = "tenant-quota:projection:write admin:write"
	if _, err := parseRuntimeConfig(nil, mapEnvironment(environment), &bytes.Buffer{}); err == nil {
		t.Fatal("over-privileged quota relay scope was accepted")
	}
}

func TestParseRuntimeConfigQuotaRelayRejectsPartialAndUnsafeConfig(t *testing.T) {
	environment := map[string]string{
		"SNAPLINK_BILLING_DEV_MEMORY": "true", "SNAPLINK_BILLING_ISSUER": "https://sso.example",
		"SNAPLINK_BILLING_AUDIENCE": "billing-api", "SNAPLINK_BILLING_QUOTA_CLIENT_ID": "partial",
	}
	if _, err := parseRuntimeConfig(nil, mapEnvironment(environment), &bytes.Buffer{}); err == nil {
		t.Fatal("partial quota relay config was accepted")
	}
	environment["SNAPLINK_BILLING_QUOTA_BASE_URL"] = "http://sso.example"
	environment["SNAPLINK_BILLING_QUOTA_CLIENT_SECRET"] = "secret"
	environment["SNAPLINK_BILLING_QUOTA_RESOURCE"] = "sso-quota-api"
	if _, err := parseRuntimeConfig(nil, mapEnvironment(environment), &bytes.Buffer{}); err == nil {
		t.Fatal("non-loopback plaintext quota relay was accepted")
	}
	delete(environment, "SNAPLINK_BILLING_QUOTA_BASE_URL")
	delete(environment, "SNAPLINK_BILLING_QUOTA_CLIENT_ID")
	delete(environment, "SNAPLINK_BILLING_QUOTA_CLIENT_SECRET")
	delete(environment, "SNAPLINK_BILLING_QUOTA_RESOURCE")
	environment["SNAPLINK_BILLING_QUOTA_MAX_LAG"] = "30m"
	if _, err := parseRuntimeConfig(nil, mapEnvironment(environment), &bytes.Buffer{}); err == nil {
		t.Fatal("orphan quota relay tuning was accepted")
	}
}

func TestParseRuntimeConfigSeparatesAuditAndQuotaCredentials(t *testing.T) {
	environment := map[string]string{
		"SNAPLINK_BILLING_DEV_MEMORY": "true", "SNAPLINK_BILLING_ISSUER": "https://sso.example",
		"SNAPLINK_BILLING_AUDIENCE": "billing-api", "SNAPLINK_BILLING_AUDIT_BASE_URL": "https://audit.example",
		"SNAPLINK_BILLING_AUDIT_CLIENT_ID": "shared-relay", "SNAPLINK_BILLING_AUDIT_CLIENT_SECRET": "shared-secret",
		"SNAPLINK_BILLING_QUOTA_BASE_URL": "https://sso.example", "SNAPLINK_BILLING_QUOTA_CLIENT_ID": "shared-relay",
		"SNAPLINK_BILLING_QUOTA_CLIENT_SECRET": "shared-secret", "SNAPLINK_BILLING_QUOTA_RESOURCE": "sso-quota-api",
	}
	if _, err := parseRuntimeConfig(nil, mapEnvironment(environment), &bytes.Buffer{}); err == nil {
		t.Fatal("shared audit/quota client identity was accepted")
	}
	environment["SNAPLINK_BILLING_QUOTA_CLIENT_ID"] = "quota-relay"
	if _, err := parseRuntimeConfig(nil, mapEnvironment(environment), &bytes.Buffer{}); err == nil {
		t.Fatal("shared audit/quota client secret was accepted")
	}
	environment["SNAPLINK_BILLING_QUOTA_CLIENT_SECRET"] = "quota-secret"
	if _, err := parseRuntimeConfig(nil, mapEnvironment(environment), &bytes.Buffer{}); err != nil {
		t.Fatalf("distinct relay credentials rejected: %v", err)
	}
}

func TestParseRuntimeConfigRetentionProjectionIsBoundedAndCredentialSeparated(t *testing.T) {
	environment := map[string]string{
		"SNAPLINK_BILLING_DEV_MEMORY": "true", "SNAPLINK_BILLING_ISSUER": "https://sso.example",
		"SNAPLINK_BILLING_AUDIENCE": "billing-api", "SNAPLINK_BILLING_QUOTA_BASE_URL": "https://sso.example",
		"SNAPLINK_BILLING_QUOTA_CLIENT_ID": "quota-relay", "SNAPLINK_BILLING_QUOTA_CLIENT_SECRET": "quota-secret",
		"SNAPLINK_BILLING_QUOTA_RESOURCE": "sso-quota-api", "SNAPLINK_BILLING_RETENTION_BASE_URL": "https://audit.example",
		"SNAPLINK_BILLING_RETENTION_CLIENT_ID":     "retention-relay",
		"SNAPLINK_BILLING_RETENTION_CLIENT_SECRET": "retention-secret",
	}
	config, err := parseRuntimeConfig(nil, mapEnvironment(environment), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if config.Retention.TokenURL != "https://sso.example/token" ||
		config.Retention.Resource != defaultAuditResource || config.Retention.HTTPTimeout != defaultRetentionTimeout {
		t.Fatalf("retention config=%+v", config.Retention)
	}
	environment["SNAPLINK_BILLING_RETENTION_CLIENT_SECRET"] = "quota-secret"
	if _, err := parseRuntimeConfig(nil, mapEnvironment(environment), &bytes.Buffer{}); err == nil {
		t.Fatal("shared quota/retention secret was accepted")
	}
	environment["SNAPLINK_BILLING_RETENTION_CLIENT_SECRET"] = "retention-secret"
	delete(environment, "SNAPLINK_BILLING_QUOTA_BASE_URL")
	if _, err := parseRuntimeConfig(nil, mapEnvironment(environment), &bytes.Buffer{}); err == nil {
		t.Fatal("retention projection without quota delivery pipeline was accepted")
	}
}

func TestParseRuntimeConfigProjectionLeaseCoversColdTokenAndWrites(t *testing.T) {
	environment := map[string]string{
		"SNAPLINK_BILLING_DEV_MEMORY": "true", "SNAPLINK_BILLING_ISSUER": "https://sso.example",
		"SNAPLINK_BILLING_AUDIENCE": "billing-api", "SNAPLINK_BILLING_QUOTA_BASE_URL": "https://sso.example",
		"SNAPLINK_BILLING_QUOTA_CLIENT_ID": "quota-relay", "SNAPLINK_BILLING_QUOTA_CLIENT_SECRET": "quota-secret",
		"SNAPLINK_BILLING_QUOTA_RESOURCE": "sso-quota-api", "SNAPLINK_BILLING_QUOTA_HTTP_TIMEOUT": "5s",
		"SNAPLINK_BILLING_QUOTA_LEASE": "10s",
	}
	if _, err := parseRuntimeConfig(nil, mapEnvironment(environment), &bytes.Buffer{}); err == nil {
		t.Fatal("lease equal to two quota HTTP windows was accepted")
	}
	environment["SNAPLINK_BILLING_QUOTA_LEASE"] = "20s"
	environment["SNAPLINK_BILLING_RETENTION_BASE_URL"] = "https://audit.example"
	environment["SNAPLINK_BILLING_RETENTION_CLIENT_ID"] = "retention-relay"
	environment["SNAPLINK_BILLING_RETENTION_CLIENT_SECRET"] = "retention-secret"
	environment["SNAPLINK_BILLING_RETENTION_HTTP_TIMEOUT"] = "5s"
	if _, err := parseRuntimeConfig(nil, mapEnvironment(environment), &bytes.Buffer{}); err == nil {
		t.Fatal("lease equal to all cold token and write windows was accepted")
	}
	environment["SNAPLINK_BILLING_QUOTA_LEASE"] = "21s"
	if _, err := parseRuntimeConfig(nil, mapEnvironment(environment), &bytes.Buffer{}); err != nil {
		t.Fatalf("adequate projection lease rejected: %v", err)
	}
}

func mapEnvironment(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}
