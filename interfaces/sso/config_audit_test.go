package sso_test

// config_audit_test.go drives the runtime-config-audit admin API
// (GET .../config/{running,applied,diff,history}) and the change-capture
// hook end to end through a real *sso.Server — the deep diff/redact/digest
// logic itself is unit-tested in platform/configaudit.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/cluster"
	"github.com/snaplink/sso/platform/cluster/memory"
	"github.com/snaplink/sso/platform/configaudit"
)

func cfgAuditGet(t *testing.T, base, path string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Get(base + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

func cfgAuditPost(t *testing.T, base, path, jsonBody string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(base+path, "application/json", strings.NewReader(jsonBody))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

func TestConfigAuditAPI_NotMountedWithoutSnapshotsOrStore(t *testing.T) {
	srv := sso.NewServer()
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	for _, path := range []string{
		"/api/v1/admin/config/running",
		"/api/v1/admin/config/applied",
		"/api/v1/admin/config/diff",
		"/api/v1/admin/config/history",
	} {
		if code, _ := cfgAuditGet(t, httpSrv.URL, path); code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 (unmounted) when no snapshot/store is wired", path, code)
		}
	}
}

func TestConfigAuditAPI_SnapshotsWiredServesRedactedRunningAppliedDiff(t *testing.T) {
	applied := map[string]any{"rate_limit": float64(10), "db_dsn": "old-secret-dsn"}
	running := map[string]any{"rate_limit": float64(20), "db_dsn": "new-secret-dsn"}

	srv := sso.NewServer(
		sso.WithConfigSnapshots(applied, func(context.Context) (map[string]any, error) { return running, nil }),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	code, body := cfgAuditGet(t, httpSrv.URL, "/api/v1/admin/config/running")
	if code != http.StatusOK {
		t.Fatalf("GET running = %d, body=%+v", code, body)
	}
	runningOut := body[configaudit.KeyRunning].(map[string]any)
	if runningOut["db_dsn"] != "***" {
		t.Errorf("running snapshot must be redacted, got %+v", runningOut)
	}
	if runningOut["rate_limit"] != float64(20) {
		t.Errorf("non-sensitive field must survive, got %+v", runningOut)
	}

	code, body = cfgAuditGet(t, httpSrv.URL, "/api/v1/admin/config/applied")
	if code != http.StatusOK {
		t.Fatalf("GET applied = %d, body=%+v", code, body)
	}
	appliedOut := body[configaudit.KeyApplied].(map[string]any)
	if appliedOut["db_dsn"] != "***" {
		t.Errorf("applied snapshot must be redacted, got %+v", appliedOut)
	}

	code, body = cfgAuditGet(t, httpSrv.URL, "/api/v1/admin/config/diff")
	if code != http.StatusOK {
		t.Fatalf("GET diff = %d, body=%+v", code, body)
	}
	patch, ok := body[configaudit.KeyPatch].([]any)
	if !ok || len(patch) != 2 {
		t.Fatalf("expected a 2-op patch (rate_limit + db_dsn changed), got %+v", body[configaudit.KeyPatch])
	}
	// History wasn't wired (no WithConfigAuditStore), so it stays unmounted
	// even though the snapshot endpoints are live.
	if code, _ := cfgAuditGet(t, httpSrv.URL, "/api/v1/admin/config/history"); code != http.StatusNotFound {
		t.Errorf("GET history = %d, want 404 without WithConfigAuditStore", code)
	}

	code, body = cfgAuditPost(t, httpSrv.URL, "/api/v1/admin/config/cluster-diff",
		`{"snapshot":{"rate_limit":10,"db_dsn":"peer-cluster-old-dsn"}}`)
	if code != http.StatusOK {
		t.Fatalf("POST cluster-diff = %d, body=%+v", code, body)
	}
	patch, ok = body[configaudit.KeyPatch].([]any)
	if !ok || len(patch) != 2 {
		t.Fatalf("expected a 2-op patch (rate_limit + db_dsn changed vs the peer snapshot), got %+v", body[configaudit.KeyPatch])
	}
	for _, raw := range patch {
		op := raw.(map[string]any)
		if op["path"] == "/db_dsn" && op["value"] != "***" {
			t.Errorf("expected /db_dsn value redacted in the cluster diff, got %+v", op)
		}
	}
}

func TestConfigAuditAPI_ClusterDiffNotMountedWithoutSnapshots(t *testing.T) {
	srv := sso.NewServer()
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	code, _ := cfgAuditPost(t, httpSrv.URL, "/api/v1/admin/config/cluster-diff", `{"snapshot":{"a":1}}`)
	if code != http.StatusNotFound {
		t.Errorf("POST cluster-diff = %d, want 404 (unmounted) when no snapshot is wired", code)
	}
}

func TestConfigAuditAPI_RunningFallsBackToAppliedWithoutRunningFn(t *testing.T) {
	applied := map[string]any{"name": "sso-1"}
	srv := sso.NewServer(sso.WithConfigSnapshots(applied, nil))
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	code, body := cfgAuditGet(t, httpSrv.URL, "/api/v1/admin/config/diff")
	if code != http.StatusOK {
		t.Fatalf("GET diff = %d, body=%+v", code, body)
	}
	patch, _ := body[configaudit.KeyPatch].([]any)
	if len(patch) != 0 {
		t.Errorf("with no live running source, running must equal applied (empty diff), got %+v", patch)
	}
}

func TestConfigAuditAPI_ChangeCaptureHookAppendsHistoryFromAuditEvents(t *testing.T) {
	store := configaudit.NewMemoryStore(0)
	sink := audit.NewMemorySink(16)
	srv := sso.NewServer(
		sso.WithAuditRecorder(audit.New(sink)),
		sso.WithConfigAuditStore(store),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	// Simulate what grpcadmin's recordAdmin helper does on every admin
	// mutation: Record an admin_* event with the actor + "target="+id Reason
	// convention. NewServer wired the ConfigChangeHook onto this SAME
	// Recorder, so this Record call alone must produce a config_history entry
	// — no direct call into platform/configaudit from this test.
	srv.Auditor().Record(context.Background(), &audit.Event{
		Type:    audit.EventAdminClientCreated,
		Outcome: audit.OutcomeSuccess,
		ActorID: "admin-1",
		Reason:  "target=client-42",
	})
	// A non client/tenant/policy admin event must NOT produce a history
	// entry (AGENTS.md scopes the hook to client/tenant/policy changes).
	srv.Auditor().Record(context.Background(), &audit.Event{
		Type:    audit.EventAdminConsentRevoked,
		Outcome: audit.OutcomeSuccess,
		ActorID: "admin-1",
		Reason:  "target=user-1",
	})

	code, body := cfgAuditGet(t, httpSrv.URL, "/api/v1/admin/config/history?resource=client")
	if code != http.StatusOK {
		t.Fatalf("GET history = %d, body=%+v", code, body)
	}
	if n, _ := body[configaudit.KeyCount].(float64); int(n) != 1 {
		t.Fatalf("count = %v, want 1 (only the client event)", body[configaudit.KeyCount])
	}
	entries, _ := body[configaudit.KeyEntries].([]any)
	entry := entries[0].(map[string]any)
	if entry["actor"] != "admin-1" || entry["resource_id"] != "client-42" || entry["resource"] != "client" {
		t.Errorf("unexpected history entry: %+v", entry)
	}
}

func TestServer_RecordConfigChange_FieldLevelDiffAndRedaction(t *testing.T) {
	store := configaudit.NewMemoryStore(0)
	srv := sso.NewServer(sso.WithConfigAuditStore(store))

	before := map[string]any{"name": "old", "client_secret": "old-secret"}
	after := map[string]any{"name": "new", "client_secret": "new-secret"}
	srv.RecordConfigChange(context.Background(), "admin-2", "tenant-1", "client", "c1", before, after, "manual_update")

	entries, err := store.List(context.Background(), configaudit.Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Actor != "admin-2" || e.TenantID != "tenant-1" || e.ResourceID != "c1" {
		t.Fatalf("unexpected entry: %+v", e)
	}
	foundNameOp, foundSecretRedacted := false, false
	for _, op := range e.Patch {
		if op.Path == "/name" && op.Value == "new" {
			foundNameOp = true
		}
		if op.Path == "/client_secret" && op.Value == "***" {
			foundSecretRedacted = true
		}
	}
	if !foundNameOp {
		t.Errorf("expected a /name replace op with the new value, got %+v", e.Patch)
	}
	if !foundSecretRedacted {
		t.Errorf("expected /client_secret redacted to ***, got %+v", e.Patch)
	}
}

func TestServer_RecordConfigChange_NoopWithoutStore(t *testing.T) {
	srv := sso.NewServer() // no WithConfigAuditStore
	// Must not panic and must be a true no-op.
	srv.RecordConfigChange(context.Background(), "a", "t", "client", "c1", nil, nil, "r")
}

func TestServer_StartConfigDriftDetection_OffByDefault(t *testing.T) {
	srv := sso.NewServer(sso.WithInvalidationBus(memory.New()))
	done, err := srv.StartConfigDriftDetection(context.Background())
	if err != nil {
		t.Fatalf("StartConfigDriftDetection: %v", err)
	}
	select {
	case <-done:
	default:
		t.Fatal("with no WithConfigDriftDetection interval, Run must return an already-closed channel")
	}
}

func TestServer_StartConfigDriftDetection_PublishesDigestAndDetectsMismatch(t *testing.T) {
	bus := memory.New()
	t.Cleanup(func() { _ = bus.Close() })

	sink := audit.NewMemorySink(16)
	srv := sso.NewServer(
		sso.WithAuditRecorder(audit.New(sink)),
		sso.WithInvalidationBus(bus),
		sso.WithConfigSnapshots(map[string]any{"a": "1"}, nil),
		sso.WithConfigDriftDetection(10*time.Millisecond, "replica-under-test"),
	)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done, err := srv.StartConfigDriftDetection(ctx)
	if err != nil {
		t.Fatalf("StartConfigDriftDetection: %v", err)
	}

	if err := bus.Publish(ctx, cluster.Event{
		Kind:    cluster.KindConfigDigest,
		Key:     "peer-replica",
		Payload: map[string]string{cluster.MetaConfigDigest: "some-other-digest"},
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && sink.Len() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if sink.Len() == 0 {
		t.Fatal("expected a config_drift_detected audit event to be recorded")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("StartConfigDriftDetection loop did not exit after ctx cancel")
	}
}
