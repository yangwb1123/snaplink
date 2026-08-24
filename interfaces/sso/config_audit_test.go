package sso_test

// config_audit_test.go drives the runtime-config-audit admin API
// (GET .../config/{running,applied,diff,history}) and the change-capture
// hook end to end through a real *sso.Server — the deep diff/redact/digest
// logic itself is unit-tested in platform/configaudit.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/cluster"
	"github.com/yangwb1123/snaplink/platform/cluster/memory"
	"github.com/yangwb1123/snaplink/platform/configaudit"
	"github.com/yangwb1123/snaplink/shared/core"
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

func fghrPost(h http.Handler, path, body string) fghrResponse {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return fghrResponse{status: rec.Code, header: rec.Header().Clone(), body: rec.Body.String()}
}

// TestConfigAudit_OperatorPaths_GateAwareTruthiness is the deploy-tree
// truthiness sweep for the operator's admin routes (R2). It drives a real
// server with const-derived paths (no literals) and asserts the three-phase
// gate contract: gate open -> GET running and POST cluster-diff answer 200,
// gate closed -> both collapse to a 404 byte-identical to
// fghrNeverMountedBaseline on the same server (oracle-safe gating, no
// header/body leak), re-open -> 200 again. Phase 1 runs on the DEFAULT gate
// state (AdminAPI unset = ON via gateOn(nil)), so a gate-default flip to
// OFF fails phase 1 — that is the flip detector. A naive sweep that only
// checks "endpoint responds" would misread the gated 404 as truthiness
// drift; byte-identity with an unmounted route is what separates "gated by
// design" from "broke". Method fidelity matters too: cluster-diff must be
// reachable via POST, not just GET, and the POST carries the snapshot body
// in all three phases — an empty-body POST is 400 (snapshot required),
// which would abort the 404 phase before gating is exercised.
func TestConfigAudit_OperatorPaths_GateAwareTruthiness(t *testing.T) {
	runningPath := core.PathAPIPrefix + core.PathAdminConfigRunning
	clusterDiffPath := core.PathAPIPrefix + core.PathAdminConfigClusterDiff
	postBody := `{"snapshot":{"rate_limit":5}}`

	applied := map[string]any{"rate_limit": float64(10)}
	running := map[string]any{"rate_limit": float64(20)}
	// No WithFeatureGates: the gate must be exercised in its default state
	// (gateOn(nil) == true) so a default flip to OFF fails phase 1.
	srv := sso.NewServer(
		sso.WithConfigSnapshots(applied, func(context.Context) (map[string]any, error) { return running, nil }),
	)
	h := srv.Handler()

	// Phase 1: gate open (default) — both deploy-tree routes answer non-404.
	if resp := fghrGet(h, runningPath); resp.status != http.StatusOK {
		t.Fatalf("GET %s with gate open = %d, want 200", runningPath, resp.status)
	}
	if resp := fghrPost(h, clusterDiffPath, postBody); resp.status != http.StatusOK {
		t.Fatalf("POST %s with gate open = %d, want 200", clusterDiffPath, resp.status)
	}

	// Phase 2: gate closed — both routes answer byte-identically to the
	// never-mounted baseline path on the same server (fghrNeverMountedBaseline
	// is immune to store-coupling churn that would flip a history baseline
	// from 404 to 200).
	if !srv.SetAdminAPIGateEnabled(false) {
		t.Fatal("SetAdminAPIGateEnabled(false) = false, want true")
	}
	baselineGET := fghrGet(h, fghrNeverMountedBaseline)
	baselinePOST := fghrPost(h, fghrNeverMountedBaseline, postBody)
	fghrAssertIdentical(t, fghrGet(h, runningPath), baselineGET, "GET running with gate closed")
	fghrAssertIdentical(t, fghrPost(h, clusterDiffPath, postBody), baselinePOST, "POST cluster-diff with gate closed")

	// Phase 3: re-open — both routes are reachable again.
	if !srv.SetAdminAPIGateEnabled(true) {
		t.Fatal("SetAdminAPIGateEnabled(true) = false, want true")
	}
	if resp := fghrGet(h, runningPath); resp.status != http.StatusOK {
		t.Fatalf("GET %s after re-open = %d, want 200", runningPath, resp.status)
	}
	if resp := fghrPost(h, clusterDiffPath, postBody); resp.status != http.StatusOK {
		t.Fatalf("POST %s after re-open = %d, want 200", clusterDiffPath, resp.status)
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

// cfgAuditPostQuery POSTs jsonBody to base+path with a raw query string.
func cfgAuditPostQuery(t *testing.T, base, path, query, jsonBody string) (int, map[string]any, string) {
	t.Helper()
	resp, err := http.Post(base+path+"?"+query, "application/json", strings.NewReader(jsonBody))
	if err != nil {
		t.Fatalf("POST %s?%s: %v", path, query, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	return resp.StatusCode, body, string(raw)
}

func applyDigest(t *testing.T, snap map[string]any) string {
	t.Helper()
	d, err := configaudit.Digest(snap)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	return d
}

func TestConfigAuditAPI_ApplyRollbackLifecycle(t *testing.T) {
	sink := audit.NewMemorySink(16)
	store := configaudit.NewMemoryStore(0)
	applied := map[string]any{"rate_limit": float64(10)}
	running := map[string]any{"rate_limit": float64(20)}
	srv := sso.NewServer(
		sso.WithAuditRecorder(audit.New(sink)),
		sso.WithConfigSnapshots(applied, func(context.Context) (map[string]any, error) { return running, nil }),
		sso.WithConfigAuditStore(store),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	// Diff-only views before any apply: byte-identical today's contract.
	code, body := cfgAuditGet(t, httpSrv.URL, "/api/v1/admin/config/applied")
	if code != http.StatusOK || body[configaudit.KeyApplied].(map[string]any)["rate_limit"] != float64(10) {
		t.Fatalf("pre-apply applied view must be the startup capture, got %d %+v", code, body)
	}

	// Apply the peer snapshot with the mandatory approval flag.
	peer := map[string]any{"rate_limit": float64(30), "db_dsn": "peer-secret-dsn"}
	applyBody := `{"snapshot":` + mustJSONString(t, peer) + `,"digest":"` + applyDigest(t, peer) + `","reason":"ticket-42"}`
	code, body, raw := cfgAuditPostQuery(t, httpSrv.URL, "/api/v1/admin/config/apply", "approve=true", applyBody)
	if code != http.StatusOK {
		t.Fatalf("apply = %d, body=%s", code, raw)
	}
	if body[configaudit.KeyVersion] == "" {
		t.Fatalf("apply response missing version: %s", raw)
	}
	if body[configaudit.KeyApplied].(map[string]any)["rate_limit"] != float64(30) {
		t.Errorf("apply response must carry the peer snapshot, got %+v", body)
	}

	// Apply a SECOND snapshot so rollback has a stored predecessor to restore.
	peer2 := map[string]any{"rate_limit": float64(40), "db_dsn": "peer2-secret-dsn"}
	apply2 := `{"snapshot":` + mustJSONString(t, peer2) + `,"digest":"` + applyDigest(t, peer2) + `","reason":"ticket-43"}`
	code, _, raw2 := cfgAuditPostQuery(t, httpSrv.URL, "/api/v1/admin/config/apply", "approve=true", apply2)
	if code != http.StatusOK {
		t.Fatalf("second apply = %d, body=%s", code, raw2)
	}

	// Applied view now serves the declared peer baseline (redacted).
	code, body = cfgAuditGet(t, httpSrv.URL, "/api/v1/admin/config/applied")
	if code != http.StatusOK {
		t.Fatalf("GET applied after apply = %d", code)
	}
	out := body[configaudit.KeyApplied].(map[string]any)
	if out["rate_limit"] != float64(40) || out["db_dsn"] != "***" {
		t.Errorf("applied view must serve the redacted peer baseline, got %+v", out)
	}

	// History carries the config apply entries.
	code, body = cfgAuditGet(t, httpSrv.URL, "/api/v1/admin/config/history?resource=config")
	if code != http.StatusOK || int(body[configaudit.KeyCount].(float64)) != 2 {
		t.Fatalf("history after applies = %d %+v", code, body)
	}

	// Approval gate: without ?approve=true the write is refused, store untouched.
	code, body, _ = cfgAuditPostQuery(t, httpSrv.URL, "/api/v1/admin/config/apply", "", applyBody)
	if code != http.StatusBadRequest || body[core.KeyError] != core.ErrConfigApplyApprovalRequired {
		t.Fatalf("apply without approval = %d %+v, want 400 %q", code, body, core.ErrConfigApplyApprovalRequired)
	}
	entries, _ := store.List(context.Background(), configaudit.Filter{Resource: "config"})
	if len(entries) != 2 {
		t.Fatalf("rejected apply must not append history, got %d entries", len(entries))
	}

	// Split-brain gate: a digest mismatch is a hard 409, store untouched.
	code, body, _ = cfgAuditPostQuery(t, httpSrv.URL, "/api/v1/admin/config/apply", "approve=true",
		`{"snapshot":{"rate_limit":99},"digest":"deadbeef","reason":"r"}`)
	if code != http.StatusConflict || body[core.KeyError] != core.ErrConfigApplyConflict {
		t.Fatalf("apply with bad digest = %d %+v, want 409 %q", code, body, core.ErrConfigApplyConflict)
	}

	// Rollback restores the FIRST applied peer baseline and audits.
	code, body, raw = cfgAuditPostQuery(t, httpSrv.URL, "/api/v1/admin/config/rollback", "approve=true", `{"reason":"revert-42"}`)
	if code != http.StatusOK {
		t.Fatalf("rollback = %d, body=%s", code, raw)
	}
	code, body = cfgAuditGet(t, httpSrv.URL, "/api/v1/admin/config/applied")
	if code != http.StatusOK || body[configaudit.KeyApplied].(map[string]any)["rate_limit"] != float64(30) {
		t.Fatalf("applied view after rollback must restore the first baseline, got %d %+v", code, body)
	}
	code, body = cfgAuditGet(t, httpSrv.URL, "/api/v1/admin/config/history?resource=config")
	if code != http.StatusOK || int(body[configaudit.KeyCount].(float64)) != 3 {
		t.Fatalf("history after rollback = %d %+v", code, body)
	}

	// Audit trail distinguishes applied from rolled back (metadata only).
	if sink.Len() != 3 {
		t.Fatalf("expected 3 audit events, got %d", sink.Len())
	}
	got, err := sink.Query(context.Background(), audit.Query{Limit: 4})
	if err != nil {
		t.Fatalf("sink Query: %v", err)
	}
	types := map[audit.EventType]bool{}
	for _, ev := range got {
		types[ev.Type] = true
	}
	if !types[audit.EventAdminConfigApplied] || !types[audit.EventAdminConfigRolledBack] {
		t.Errorf("expected apply + rollback audit events, got %v", types)
	}
	if strings.Contains(raw, "peer-secret-dsn") {
		t.Error("rollback response leaks a secret")
	}
}

func TestConfigAuditAPI_ApplyRollbackUnmountedWithoutStoreOrSnapshots(t *testing.T) {
	srv := sso.NewServer()
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	for _, path := range []string{"/api/v1/admin/config/apply", "/api/v1/admin/config/rollback"} {
		code, _, _ := cfgAuditPostQuery(t, httpSrv.URL, path, "approve=true", `{"snapshot":{"a":1},"digest":"x","reason":"r"}`)
		if code != http.StatusNotFound {
			t.Errorf("POST %s = %d, want 404 (unmounted) without store+snapshots", path, code)
		}
	}

	// Snapshots WITHOUT a store: snapshot routes live, apply/rollback stay 404.
	srv2 := sso.NewServer(sso.WithConfigSnapshots(map[string]any{"a": 1}, nil))
	httpSrv2 := httptest.NewServer(srv2.Handler())
	t.Cleanup(httpSrv2.Close)
	code, _, _ := cfgAuditPostQuery(t, httpSrv2.URL, "/api/v1/admin/config/apply", "approve=true", `{"snapshot":{"a":1},"digest":"x","reason":"r"}`)
	if code != http.StatusNotFound {
		t.Errorf("apply without a store = %d, want 404", code)
	}

	// Store WITHOUT snapshots: history lives, apply/rollback stay 404.
	srv3 := sso.NewServer(sso.WithConfigAuditStore(configaudit.NewMemoryStore(0)))
	httpSrv3 := httptest.NewServer(srv3.Handler())
	t.Cleanup(httpSrv3.Close)
	code, _, _ = cfgAuditPostQuery(t, httpSrv3.URL, "/api/v1/admin/config/apply", "approve=true", `{"snapshot":{"a":1},"digest":"x","reason":"r"}`)
	if code != http.StatusNotFound {
		t.Errorf("apply without snapshots = %d, want 404", code)
	}
	if code, _ := cfgAuditGet(t, httpSrv3.URL, "/api/v1/admin/config/history"); code != http.StatusOK {
		t.Errorf("history with only a store must stay mounted, got %d", code)
	}
}

func mustJSONString(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
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
