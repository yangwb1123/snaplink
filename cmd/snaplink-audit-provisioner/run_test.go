package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/auditgovernance"
)

type controlFixture struct {
	mu      sync.Mutex
	tenants []auditgovernance.TenantRecord
	sources []auditgovernance.SourceRecord
	schemas []auditgovernance.SchemaRecord
}

func TestExecuteOneShotConvergesTenantSourceAndSchema(t *testing.T) {
	fixture := &controlFixture{}
	server := httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	defer server.Close()
	manifest := filepath.Join(t.TempDir(), "desired.json")
	if err := os.WriteFile(manifest, []byte(testManifestJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"SNAPLINK_AUDIT_PROVISIONER_MANIFEST_FILE":           manifest,
		"SNAPLINK_AUDIT_PROVISIONER_BASE_URL":                server.URL,
		"SNAPLINK_AUDIT_PROVISIONER_TOKEN_URL":               server.URL + "/token",
		"SNAPLINK_AUDIT_PROVISIONER_CLIENT_ID":               "provisioner",
		"SNAPLINK_AUDIT_PROVISIONER_CLIENT_SECRET":           "secret",
		"SNAPLINK_AUDIT_PROVISIONER_RESOURCE":                "audit-control",
		"SNAPLINK_AUDIT_PROVISIONER_ALLOW_INSECURE_LOOPBACK": "true",
	}
	var stdout, stderr bytes.Buffer
	code := execute(t.Context(), []string{"--one-shot"}, &stdout, &stderr, mapGetenv(env), nil)
	if code != 0 || !strings.Contains(stdout.String(), "schemas_created=1") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if len(fixture.tenants) != 1 || len(fixture.sources) != 1 || len(fixture.schemas) != 1 {
		t.Fatalf("fixture=%+v", fixture)
	}
}

func TestBoundedLoggerReportsAppliedRevisionChanges(t *testing.T) {
	var output bytes.Buffer
	logger := &boundedReconcileLogger{output: &output}
	logger.log("success", auditgovernance.ReconcileResult{Revision: 1})
	logger.log("success", auditgovernance.ReconcileResult{Revision: 2})
	if strings.Count(output.String(), "reconcile result=success") != 2 {
		t.Fatalf("revision transition was suppressed: %q", output.String())
	}
}

func (fixture *controlFixture) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	writer.Header().Set("Content-Type", "application/json")
	if request.URL.Path == "/token" {
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"access_token": "platform-token", "token_type": "Bearer", "expires_in": 300,
		})
		return
	}
	if request.Header.Get("Authorization") != "Bearer platform-token" {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch request.Method + " " + request.URL.Path {
	case "GET /api/v1/tenants":
		writeFixtureList(writer, fixture.tenants)
	case "POST /api/v1/tenants":
		createFixtureItem(writer, request, &fixture.tenants)
	case "GET /api/v1/sources":
		writeFixtureList(writer, fixture.sources)
	case "POST /api/v1/sources":
		createFixtureItem(writer, request, &fixture.sources)
	case "GET /api/v1/schemas":
		writeFixtureList(writer, fixture.schemas)
	case "POST /api/v1/schemas":
		createFixtureItem(writer, request, &fixture.schemas)
	default:
		writer.WriteHeader(http.StatusNotFound)
	}
}

func writeFixtureList[T any](writer http.ResponseWriter, items []T) {
	_ = json.NewEncoder(writer).Encode(map[string]any{"items": items, "count": len(items)})
}

func createFixtureItem[T any](writer http.ResponseWriter, request *http.Request, items *[]T) {
	var item T
	if err := json.NewDecoder(request.Body).Decode(&item); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	*items = append(*items, item)
	writer.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(writer).Encode(item)
}

const testManifestJSON = `{
  "revision": 1,
  "tenants": [{"id":"tenant-a","name":"Tenant A","home_region":"","data_region":"","active":true,"events_per_second":100,"burst":20}],
  "sources": [{"tenant_id":"tenant-a","prefix":"aero-id","name":"Aero ID","allowed_client_ids":["aero-id-relay"],"active":true}],
  "schemas": [{"tenant_id":"tenant-a","schema_id":"aero.id.audit-fact","version":1,"event_type":"aero.id.audit-fact","required_fields":[],"allowed_fields":[],"encrypted_fields":[],"searchable_fields":[],"classification":"personal","active":true}]
}`
