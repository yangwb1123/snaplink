package configaudit_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/configaudit"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// noopLogger satisfies spi.Logger without printing anything.
type noopLogger struct{}

func (noopLogger) Info(string, ...any)  {}
func (noopLogger) Error(string, ...any) {}
func (noopLogger) Debug(string, ...any) {}

// handlerDeps is the minimal configaudit.HandlerDeps *sso.Server satisfies
// in production via its own accessor methods (interfaces/sso/accessors.go).
type handlerDeps struct {
	store      configaudit.Store
	applied    map[string]any
	appliedErr error
	running    map[string]any
	runningErr error
	auditor    *audit.Recorder
	actor      string
	controller *configaudit.CanaryController
}

func (d handlerDeps) ConfigAuditStore() configaudit.Store { return d.store }
func (d handlerDeps) AppliedConfigSnapshot() (map[string]any, error) {
	return d.applied, d.appliedErr
}
func (d handlerDeps) RunningConfigSnapshot(context.Context) (map[string]any, error) {
	return d.running, d.runningErr
}
func (d handlerDeps) SrvLogger() spi.Logger { return noopLogger{} }
func (d handlerDeps) Auditor() *audit.Recorder {
	return d.auditor
}
func (d handlerDeps) ActorFromContext(context.Context) (string, string, bool) {
	return d.actor, "", d.actor != ""
}
func (d handlerDeps) ConfigCanaryController() *configaudit.CanaryController { return d.controller }

func httpCtx(rawQuery string) (core.HandlerContext, *httptest.ResponseRecorder) {
	r := httptest.NewRequest("GET", "/api/v1/admin/config/history?"+rawQuery, nil)
	w := httptest.NewRecorder()
	return core.NewContext(w, r), w
}

func httpCtxPOST(body string) (core.HandlerContext, *httptest.ResponseRecorder) {
	r := httptest.NewRequest("POST", "/api/v1/admin/config/cluster-diff", strings.NewReader(body))
	w := httptest.NewRecorder()
	return core.NewContext(w, r), w
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode body %q: %v", w.Body.String(), err)
	}
	return m
}

func TestHandleRunning_RedactsAndReturns200(t *testing.T) {
	d := handlerDeps{running: map[string]any{"db_dsn": "secret-dsn", "name": "sso"}}
	ctx, w := httpCtx("")
	configaudit.HandleRunning(d, ctx)
	if w.Code != 200 {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	running, ok := body[configaudit.KeyRunning].(map[string]any)
	if !ok {
		t.Fatalf("missing %q key: %s", configaudit.KeyRunning, w.Body.String())
	}
	if running["db_dsn"] != "***" {
		t.Errorf("expected running snapshot to be redacted, got %+v", running)
	}
	if running["name"] != "sso" {
		t.Errorf("non-sensitive field must survive, got %+v", running)
	}
}

func TestHandleApplied_RedactsAndReturns200(t *testing.T) {
	d := handlerDeps{applied: map[string]any{"client_secret": "abc"}}
	ctx, w := httpCtx("")
	configaudit.HandleApplied(d, ctx)
	if w.Code != 200 {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	applied := decodeBody(t, w)[configaudit.KeyApplied].(map[string]any)
	if applied["client_secret"] != "***" {
		t.Errorf("expected applied snapshot to be redacted, got %+v", applied)
	}
}

func TestHandleRunning_Unavailable501(t *testing.T) {
	d := handlerDeps{runningErr: configaudit.ErrSnapshotUnavailable}
	ctx, w := httpCtx("")
	configaudit.HandleRunning(d, ctx)
	if w.Code != 501 {
		t.Fatalf("status = %d, want 501, body=%s", w.Code, w.Body.String())
	}
	if decodeBody(t, w)[core.KeyError] != configaudit.ErrNotAvailable {
		t.Fatalf("error = %v, want %q", decodeBody(t, w)[core.KeyError], configaudit.ErrNotAvailable)
	}
}

func TestHandleDiff_ReturnsRedactedPatch(t *testing.T) {
	d := handlerDeps{
		applied: map[string]any{"rate_limit": float64(10), "db_dsn": "old-dsn"},
		running: map[string]any{"rate_limit": float64(20), "db_dsn": "new-dsn"},
	}
	ctx, w := httpCtx("")
	configaudit.HandleDiff(d, ctx)
	if w.Code != 200 {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	patch, ok := decodeBody(t, w)[configaudit.KeyPatch].([]any)
	if !ok || len(patch) != 2 {
		t.Fatalf("expected a 2-op patch, got %+v", decodeBody(t, w)[configaudit.KeyPatch])
	}
	for _, raw := range patch {
		op := raw.(map[string]any)
		if op["path"] == "/db_dsn" && op["value"] != "***" {
			t.Errorf("expected /db_dsn value redacted in the diff, got %+v", op)
		}
		if op["path"] == "/rate_limit" && op["value"] != float64(20) {
			t.Errorf("expected /rate_limit value preserved, got %+v", op)
		}
	}
}

func TestHandleDiff_AppliedUnavailable501(t *testing.T) {
	d := handlerDeps{appliedErr: configaudit.ErrSnapshotUnavailable}
	ctx, w := httpCtx("")
	configaudit.HandleDiff(d, ctx)
	if w.Code != 501 {
		t.Fatalf("status = %d, want 501", w.Code)
	}
}

func TestHandleClusterDiff_ReturnsRedactedPatchAgainstPeerSnapshot(t *testing.T) {
	d := handlerDeps{running: map[string]any{"rate_limit": float64(20), "db_dsn": "new-dsn"}}
	ctx, w := httpCtxPOST(`{"snapshot":{"rate_limit":10,"db_dsn":"old-dsn"}}`)
	configaudit.HandleClusterDiff(d, ctx)
	if w.Code != 200 {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	patch, ok := decodeBody(t, w)[configaudit.KeyPatch].([]any)
	if !ok || len(patch) != 2 {
		t.Fatalf("expected a 2-op patch, got %+v", decodeBody(t, w)[configaudit.KeyPatch])
	}
	for _, raw := range patch {
		op := raw.(map[string]any)
		if op["path"] == "/db_dsn" && op["value"] != "***" {
			t.Errorf("expected /db_dsn value redacted in the diff, got %+v", op)
		}
		if op["path"] == "/rate_limit" && op["value"] != float64(20) {
			t.Errorf("expected /rate_limit value preserved (this cluster's own), got %+v", op)
		}
	}
}

func TestHandleClusterDiff_EmptySnapshot400(t *testing.T) {
	d := handlerDeps{running: map[string]any{"a": 1}}
	ctx, w := httpCtxPOST(`{}`)
	configaudit.HandleClusterDiff(d, ctx)
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400, body=%s", w.Code, w.Body.String())
	}
}

func TestHandleClusterDiff_MalformedBody400(t *testing.T) {
	d := handlerDeps{running: map[string]any{"a": 1}}
	ctx, w := httpCtxPOST(`not-json`)
	configaudit.HandleClusterDiff(d, ctx)
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400, body=%s", w.Code, w.Body.String())
	}
}

func TestHandleClusterDiff_RunningUnavailable501(t *testing.T) {
	d := handlerDeps{runningErr: configaudit.ErrSnapshotUnavailable}
	ctx, w := httpCtxPOST(`{"snapshot":{"a":1}}`)
	configaudit.HandleClusterDiff(d, ctx)
	if w.Code != 501 {
		t.Fatalf("status = %d, want 501, body=%s", w.Code, w.Body.String())
	}
}

func TestHandleHistory_NoStore501(t *testing.T) {
	d := handlerDeps{}
	ctx, w := httpCtx("")
	configaudit.HandleHistory(d, ctx)
	if w.Code != 501 {
		t.Fatalf("status = %d, want 501", w.Code)
	}
}

func TestHandleHistory_ReturnsEntriesAndCount(t *testing.T) {
	store := configaudit.NewMemoryStore(0)
	_ = store.Record(context.Background(), configaudit.Entry{Actor: "alice", Resource: "client", ResourceID: "c1"})
	_ = store.Record(context.Background(), configaudit.Entry{Actor: "bob", Resource: "tenant", ResourceID: "t1"})

	d := handlerDeps{store: store}
	ctx, w := httpCtx("resource=client")
	configaudit.HandleHistory(d, ctx)
	if w.Code != 200 {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if n, _ := body[configaudit.KeyCount].(float64); int(n) != 1 {
		t.Fatalf("count = %v, want 1", body[configaudit.KeyCount])
	}
}

func TestHandleHistory_BadSince400(t *testing.T) {
	store := configaudit.NewMemoryStore(0)
	d := handlerDeps{store: store}
	ctx, w := httpCtx("since=not-a-time")
	configaudit.HandleHistory(d, ctx)
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandleHistory_BadLimit400(t *testing.T) {
	store := configaudit.NewMemoryStore(0)
	d := handlerDeps{store: store}
	ctx, w := httpCtx("limit=NaN")
	configaudit.HandleHistory(d, ctx)
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

// httpCtxApply builds a POST apply/rollback request with query + body.
func httpCtxApply(path, rawQuery, body string) (core.HandlerContext, *httptest.ResponseRecorder) {
	r := httptest.NewRequest("POST", path+"?"+rawQuery, strings.NewReader(body))
	w := httptest.NewRecorder()
	return core.NewContext(w, r), w
}

// sinkEvents reads every event a MemorySink holds, newest first.
func sinkEvents(t *testing.T, sink *audit.MemorySink) []*audit.Event {
	t.Helper()
	evts, err := sink.Query(context.Background(), audit.Query{Limit: 64})
	if err != nil {
		t.Fatalf("sink Query: %v", err)
	}
	return evts
}

func digestOf(t *testing.T, snap map[string]any) string {
	t.Helper()
	d, err := configaudit.Digest(snap)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	return d
}

func TestHandleApply_Success_RecordsBaselineHistoryAndAudit(t *testing.T) {
	sink := audit.NewMemorySink(8)
	store := configaudit.NewMemoryStore(0)
	peer := map[string]any{"rate_limit": float64(30), "db_dsn": "peer-secret-dsn"}
	body := `{"snapshot":{"rate_limit":30,"db_dsn":"peer-secret-dsn"},"digest":"` +
		digestOf(t, peer) + `","reason":"ticket-123"}`
	d := handlerDeps{store: store, running: map[string]any{"rate_limit": float64(20)}, auditor: audit.New(sink), actor: "admin-9"}
	ctx, w := httpCtxApply("/api/v1/admin/config/apply", "approve=true", body)
	configaudit.HandleApply(d, ctx)
	if w.Code != 200 {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	resp := decodeBody(t, w)
	if resp[configaudit.KeyVersion] == "" {
		t.Fatalf("response missing version: %s", w.Body.String())
	}
	applied, ok := resp[configaudit.KeyApplied].(map[string]any)
	if !ok {
		t.Fatalf("response missing applied snapshot: %s", w.Body.String())
	}
	if applied["rate_limit"] != float64(30) {
		t.Errorf("applied snapshot must carry the peer's rate_limit, got %+v", applied)
	}
	if applied["db_dsn"] != "***" {
		t.Errorf("applied snapshot must be redacted, got %+v", applied)
	}
	patch, _ := resp[configaudit.KeyPatch].([]any)
	if len(patch) != 2 {
		t.Errorf("expected a 2-op informational patch (rate_limit + db_dsn vs running), got %+v", patch)
	}
	// Applied view: the store now reports the peer baseline.
	v, err := store.Applied(context.Background())
	if err != nil {
		t.Fatalf("Applied: %v", err)
	}
	if v.ID == "" || v.AppliedAt.IsZero() || v.PrevID != "" {
		t.Errorf("unexpected first version: %+v", v)
	}
	if v.Snapshot["db_dsn"] != "***" {
		t.Errorf("stored baseline must be redacted, got %+v", v.Snapshot)
	}
	// History view: one config entry with the redacted patch.
	entries, err := store.List(context.Background(), configaudit.Filter{Resource: "config"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].ResourceID != v.ID || entries[0].Actor != "admin-9" {
		t.Fatalf("unexpected history entries: %+v", entries)
	}
	for _, op := range entries[0].Patch {
		if op.Path == "/db_dsn" && op.Value != "***" {
			t.Errorf("history patch must be redacted, got %+v", entries[0].Patch)
		}
	}
	// Audit event with the evidence chain, metadata only.
	if sink.Len() != 1 {
		t.Fatalf("expected 1 audit event, got %d", sink.Len())
	}
	evs := sinkEvents(t, sink)
	ev := evs[0]
	if ev.Type != audit.EventAdminConfigApplied || ev.ActorID != "admin-9" {
		t.Fatalf("unexpected audit event: %+v", ev)
	}
	if ev.Metadata["apply_id"] != v.ID || ev.Metadata["peer_digest"] != digestOf(t, peer) {
		t.Errorf("audit evidence chain incomplete: %+v", ev.Metadata)
	}
}

func TestHandleApply_NoApproval400(t *testing.T) {
	store := configaudit.NewMemoryStore(0)
	d := handlerDeps{store: store, running: map[string]any{"a": 1}}
	ctx, w := httpCtxApply("/api/v1/admin/config/apply", "", `{"snapshot":{"a":1},"digest":"`+digestOf(t, map[string]any{"a": 1})+`","reason":"r"}`)
	configaudit.HandleApply(d, ctx)
	if w.Code != 400 || decodeBody(t, w)[core.KeyError] != core.ErrConfigApplyApprovalRequired {
		t.Fatalf("status = %d body=%s, want 400 %q", w.Code, w.Body.String(), core.ErrConfigApplyApprovalRequired)
	}
	if _, err := store.Applied(context.Background()); err != configaudit.ErrNoAppliedVersion {
		t.Fatalf("no-approval apply must not touch the store, got err=%v", err)
	}
}

func TestHandleApply_DigestMismatch409(t *testing.T) {
	store := configaudit.NewMemoryStore(0)
	d := handlerDeps{store: store, running: map[string]any{"a": 1}}
	body := `{"snapshot":{"a":1},"digest":"deadbeef","reason":"r"}`
	ctx, w := httpCtxApply("/api/v1/admin/config/apply", "approve=true", body)
	configaudit.HandleApply(d, ctx)
	if w.Code != 409 || decodeBody(t, w)[core.KeyError] != core.ErrConfigApplyConflict {
		t.Fatalf("status = %d body=%s, want 409 %q", w.Code, w.Body.String(), core.ErrConfigApplyConflict)
	}
	if _, err := store.Applied(context.Background()); err != configaudit.ErrNoAppliedVersion {
		t.Fatalf("conflict apply must not touch the store, got err=%v", err)
	}
}

func TestHandleApply_CanaryStartsAndBlocksConcurrentApply(t *testing.T) {
	store := configaudit.NewMemoryStore(0)
	if _, err := store.Apply(context.Background(), configaudit.AppliedVersion{
		Actor: "seed", Digest: "d1", Snapshot: map[string]any{"version": 1},
	}); err != nil {
		t.Fatalf("seed baseline: %v", err)
	}
	sink := audit.NewMemorySink(8)
	controller := configaudit.NewCanaryController(store, []configaudit.CanaryProbe{{
		Name: "db", Check: func(context.Context) configaudit.CanaryHealth { return configaudit.CanaryHealthy },
	}}, nil, audit.New(sink))
	d := handlerDeps{store: store, running: map[string]any{"version": 1}, auditor: audit.New(sink), actor: "admin-9", controller: controller}
	peer := map[string]any{"version": 2}
	body := `{"snapshot":` + mustJSON(t, peer) + `,"digest":"` + digestOf(t, peer) + `","reason":"ticket-2"}`
	ctx, w := httpCtxApply("/api/v1/admin/config/apply", "approve=true&canary=true&window=1s", body)
	configaudit.HandleApply(d, ctx)
	if w.Code != 200 {
		t.Fatalf("canary apply status = %d body=%s", w.Code, w.Body.String())
	}
	response := decodeBody(t, w)
	canary, ok := response[configaudit.KeyCanary].(map[string]any)
	if !ok || canary["status"] != string(configaudit.CanaryObserving) {
		t.Fatalf("canary response = %+v", response[configaudit.KeyCanary])
	}
	third := map[string]any{"version": 3}
	thirdBody := `{"snapshot":` + mustJSON(t, third) + `,"digest":"` + digestOf(t, third) + `","reason":"ticket-3"}`
	ctx, w = httpCtxApply("/api/v1/admin/config/apply", "approve=true", thirdBody)
	configaudit.HandleApply(d, ctx)
	if w.Code != 409 || decodeBody(t, w)[core.KeyError] != core.ErrConfigCanaryInProgress {
		t.Fatalf("concurrent apply status = %d body=%s", w.Code, w.Body.String())
	}
	if events, err := sink.Query(context.Background(), audit.Query{Limit: 8}); err != nil {
		t.Fatalf("query canary audit: %v", err)
	} else if len(events) != 2 {
		t.Fatalf("canary start should emit baseline + lifecycle audit, got %+v", events)
	}
}

func TestHandleApply_CanaryNeedsPreviousBaseline(t *testing.T) {
	store := configaudit.NewMemoryStore(0)
	controller := configaudit.NewCanaryController(store, []configaudit.CanaryProbe{{
		Name: "db", Check: func(context.Context) configaudit.CanaryHealth { return configaudit.CanaryHealthy },
	}}, nil, nil)
	peer := map[string]any{"version": 1}
	d := handlerDeps{store: store, running: map[string]any{}, controller: controller}
	body := `{"snapshot":` + mustJSON(t, peer) + `,"digest":"` + digestOf(t, peer) + `","reason":"ticket-1"}`
	ctx, w := httpCtxApply("/api/v1/admin/config/apply", "approve=true&canary=true", body)
	configaudit.HandleApply(d, ctx)
	if w.Code != 409 || decodeBody(t, w)[core.KeyError] != core.ErrConfigCanaryNoBaseline {
		t.Fatalf("first canary status = %d body=%s", w.Code, w.Body.String())
	}
}

func TestHandleApply_MissingSnapshotOrFields400(t *testing.T) {
	store := configaudit.NewMemoryStore(0)
	d := handlerDeps{store: store}
	for _, body := range []string{
		`{}`,
		`{"snapshot":{"a":1},"digest":"` + digestOf(t, map[string]any{"a": 1}) + `"}`,
		`{"snapshot":{"a":1},"reason":"r"}`,
		`not-json`,
	} {
		ctx, w := httpCtxApply("/api/v1/admin/config/apply", "approve=true", body)
		configaudit.HandleApply(d, ctx)
		if w.Code != 400 {
			t.Errorf("body %q => status %d, want 400 (%s)", body, w.Code, w.Body.String())
		}
	}
}

func TestHandleApply_NoStore501(t *testing.T) {
	d := handlerDeps{}
	ctx, w := httpCtxApply("/api/v1/admin/config/apply", "approve=true", `{"snapshot":{"a":1},"digest":"x","reason":"r"}`)
	configaudit.HandleApply(d, ctx)
	if w.Code != 501 {
		t.Fatalf("status = %d, want 501", w.Code)
	}
}

func TestHandleRollback_RestoresPreviousVersion(t *testing.T) {
	sink := audit.NewMemorySink(8)
	store := configaudit.NewMemoryStore(0)
	d := handlerDeps{store: store, running: map[string]any{"rate_limit": float64(20)}, auditor: audit.New(sink), actor: "admin-9"}
	first := map[string]any{"rate_limit": float64(10)}
	second := map[string]any{"rate_limit": float64(40)}
	apply := func(snap map[string]any) {
		t.Helper()
		body := `{"snapshot":` + mustJSON(t, snap) + `,"digest":"` + digestOf(t, snap) + `","reason":"r"}`
		ctx, w := httpCtxApply("/api/v1/admin/config/apply", "approve=true", body)
		configaudit.HandleApply(d, ctx)
		if w.Code != 200 {
			t.Fatalf("apply status = %d body=%s", w.Code, w.Body.String())
		}
	}
	apply(first)
	apply(second)

	ctx, w := httpCtxApply("/api/v1/admin/config/rollback", "approve=true", `{"reason":"rollback-ticket"}`)
	configaudit.HandleRollback(d, ctx)
	if w.Code != 200 {
		t.Fatalf("rollback status = %d body=%s", w.Code, w.Body.String())
	}
	resp := decodeBody(t, w)
	applied, _ := resp[configaudit.KeyApplied].(map[string]any)
	if applied["rate_limit"] != float64(10) {
		t.Errorf("rollback must restore the FIRST snapshot, got %+v", applied)
	}
	v, err := store.Applied(context.Background())
	if err != nil {
		t.Fatalf("Applied: %v", err)
	}
	if v.Snapshot["rate_limit"] != float64(10) || v.PrevID == "" {
		t.Errorf("restored version must be append-only with a prev link, got %+v", v)
	}
	entries, err := store.List(context.Background(), configaudit.Filter{Resource: "config"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 config entries (2 applies + 1 rollback), got %d", len(entries))
	}
	if evs := sinkEvents(t, sink); len(evs) != 3 || evs[0].Type != audit.EventAdminConfigRolledBack {
		t.Fatalf("expected newest audit event to be rollback, got %+v", evs)
	}
}

func TestHandleRollback_NoPrevious409(t *testing.T) {
	store := configaudit.NewMemoryStore(0)
	d := handlerDeps{store: store}
	ctx, w := httpCtxApply("/api/v1/admin/config/rollback", "approve=true", `{"reason":"r"}`)
	configaudit.HandleRollback(d, ctx)
	if w.Code != 409 || decodeBody(t, w)[core.KeyError] != core.ErrConfigApplyNoPrevious {
		t.Fatalf("status = %d body=%s, want 409 %q", w.Code, w.Body.String(), core.ErrConfigApplyNoPrevious)
	}
}

func TestHandleRollback_NoApproval400(t *testing.T) {
	store := configaudit.NewMemoryStore(0)
	d := handlerDeps{store: store}
	ctx, w := httpCtxApply("/api/v1/admin/config/rollback", "", `{"reason":"r"}`)
	configaudit.HandleRollback(d, ctx)
	if w.Code != 400 || decodeBody(t, w)[core.KeyError] != core.ErrConfigApplyApprovalRequired {
		t.Fatalf("status = %d body=%s, want 400 %q", w.Code, w.Body.String(), core.ErrConfigApplyApprovalRequired)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}

// TestHandleApply_PlaintextSecretNeverEchoed scans every artifact an apply
// produces (stored history entries, stored baseline, response body, audit
// event) for the submitted plaintext secrets — the redaction proof the
// deferred-backlog boundary demands.
func TestHandleApply_PlaintextSecretNeverEchoed(t *testing.T) {
	sink := audit.NewMemorySink(8)
	store := configaudit.NewMemoryStore(0)
	peer := map[string]any{
		"rate_limit":   float64(5),
		"db_dsn":       "postgres://user:sup3r-plaintext-pass@host/db",
		"client_token": "tok_plaintext_xyz",
	}
	body := `{"snapshot":` + mustJSON(t, peer) + `,"digest":"` + digestOf(t, peer) + `","reason":"r"}`
	d := handlerDeps{store: store, running: map[string]any{}, auditor: audit.New(sink), actor: "admin-1"}
	ctx, w := httpCtxApply("/api/v1/admin/config/apply", "approve=true", body)
	configaudit.HandleApply(d, ctx)
	if w.Code != 200 {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	needles := []string{"sup3r-plaintext-pass", "tok_plaintext_xyz", "user:"}
	// (a) response body
	resp := w.Body.String()
	for _, n := range needles {
		if strings.Contains(resp, n) {
			t.Errorf("response body leaks %q: %s", n, resp)
		}
	}
	// (b) stored baseline
	v, err := store.Applied(context.Background())
	if err != nil {
		t.Fatalf("Applied: %v", err)
	}
	rawBaseline := mustJSON(t, v.Snapshot)
	// (c) stored history entries
	entries, err := store.List(context.Background(), configaudit.Filter{Resource: "config"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	rawHistory := mustJSON(t, entries)
	// (d) audit events
	rawAudit := mustJSON(t, sinkEvents(t, sink))
	for _, n := range needles {
		if strings.Contains(rawBaseline, n) {
			t.Errorf("stored baseline leaks %q: %s", n, rawBaseline)
		}
		if strings.Contains(rawHistory, n) {
			t.Errorf("history entries leak %q: %s", n, rawHistory)
		}
		if strings.Contains(rawAudit, n) {
			t.Errorf("audit event leaks %q: %s", n, rawAudit)
		}
	}
}
