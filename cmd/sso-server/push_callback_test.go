package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/defaultimpl"
	sqlitestores "github.com/snaplink/sso/defaultimpl/sqlite"
)

func newCallbackTestStore(t *testing.T) (*sqlitestores.PushApprovalStore, string) {
	t.Helper()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "push.db") + "?_journal=WAL"
	s, err := sqlitestores.NewPushApprovalStore(dsn)
	if err != nil {
		t.Fatalf("NewPushApprovalStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dsn
}

func seedApproval(t *testing.T, s *sqlitestores.PushApprovalStore, id string) {
	t.Helper()
	now := time.Now().UTC()
	if err := s.Put(context.Background(), &defaultimpl.PushApproval{
		ID:        id,
		SubjectID: "alice",
		Status:    defaultimpl.PushApprovalPending,
		CreatedAt: now,
		ExpiresAt: now.Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
}

func callCallback(t *testing.T, deps *pushCallbackDeps, urlPath, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, urlPath, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	pushCallbackHandler(deps)(rec, req)
	return rec
}

func TestPushCallback_ApproveHappy(t *testing.T) {
	store, _ := newCallbackTestStore(t)
	seedApproval(t, store, "ch-1")
	deps := &pushCallbackDeps{Store: store, Logger: quietLogger()}

	rec := callCallback(t, deps, "/push/approval/ch-1/approve", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	got, _ := store.Get(context.Background(), "ch-1")
	if got.Status != defaultimpl.PushApprovalApproved {
		t.Errorf("status = %v, want approved", got.Status)
	}
}

func TestPushCallback_DenyHappy(t *testing.T) {
	store, _ := newCallbackTestStore(t)
	seedApproval(t, store, "ch-2")
	deps := &pushCallbackDeps{Store: store, Logger: quietLogger()}

	rec := callCallback(t, deps, "/push/approval/ch-2/deny", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	got, _ := store.Get(context.Background(), "ch-2")
	if got.Status != defaultimpl.PushApprovalDenied {
		t.Errorf("status = %v, want denied", got.Status)
	}
}

func TestPushCallback_InvalidDecisionRejected(t *testing.T) {
	store, _ := newCallbackTestStore(t)
	seedApproval(t, store, "ch-3")
	deps := &pushCallbackDeps{Store: store, Logger: quietLogger()}

	rec := callCallback(t, deps, "/push/approval/ch-3/whatever", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	body, _ := decodeCallbackError(rec)
	if body["error"] != "invalid_decision" {
		t.Errorf("error = %v, want invalid_decision", body["error"])
	}
}

func TestPushCallback_UnknownApprovalReturnsNotFound(t *testing.T) {
	store, _ := newCallbackTestStore(t)
	deps := &pushCallbackDeps{Store: store, Logger: quietLogger()}

	rec := callCallback(t, deps, "/push/approval/ghost/approve", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPushCallback_DoubleResolutionReturnsConflict(t *testing.T) {
	store, _ := newCallbackTestStore(t)
	seedApproval(t, store, "ch-4")
	deps := &pushCallbackDeps{Store: store, Logger: quietLogger()}

	if rec := callCallback(t, deps, "/push/approval/ch-4/approve", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("first approve: %d", rec.Code)
	}
	// Trying to flip to deny after approval — operator audit signal.
	rec := callCallback(t, deps, "/push/approval/ch-4/deny", "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d body=%s, want 409", rec.Code, rec.Body.String())
	}
}

func TestPushCallback_MissingBearerRejected(t *testing.T) {
	store, _ := newCallbackTestStore(t)
	seedApproval(t, store, "ch-5")
	deps := &pushCallbackDeps{Store: store, BearerToken: "expected-token", Logger: quietLogger()}

	// No Authorization header → 401.
	req := httptest.NewRequest(http.MethodPost, "/push/approval/ch-5/approve", nil)
	rec := httptest.NewRecorder()
	pushCallbackHandler(deps)(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s, want 401", rec.Code, rec.Body.String())
	}
	body, _ := decodeCallbackError(rec)
	if body["error"] != "missing_bearer" {
		t.Errorf("error = %v, want missing_bearer", body["error"])
	}
}

func TestPushCallback_WrongBearerRejected(t *testing.T) {
	store, _ := newCallbackTestStore(t)
	seedApproval(t, store, "ch-6")
	deps := &pushCallbackDeps{Store: store, BearerToken: "expected-token", Logger: quietLogger()}

	rec := callCallback(t, deps, "/push/approval/ch-6/approve", "wrong-token")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	body, _ := decodeCallbackError(rec)
	if body["error"] != "invalid_bearer" {
		t.Errorf("error = %v, want invalid_bearer", body["error"])
	}
}

func TestPushCallback_CorrectBearerAccepted(t *testing.T) {
	store, _ := newCallbackTestStore(t)
	seedApproval(t, store, "ch-7")
	deps := &pushCallbackDeps{Store: store, BearerToken: "expected-token", Logger: quietLogger()}

	rec := callCallback(t, deps, "/push/approval/ch-7/approve", "expected-token")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPushCallback_IPAllowlistBlocks(t *testing.T) {
	store, _ := newCallbackTestStore(t)
	seedApproval(t, store, "ch-8")
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	deps := &pushCallbackDeps{
		Store:        store,
		AllowedCIDRs: []*net.IPNet{cidr},
		Logger:       quietLogger(),
	}
	// Request from 192.168.1.1 — outside the allowlist.
	req := httptest.NewRequest(http.MethodPost, "/push/approval/ch-8/approve", nil)
	req.RemoteAddr = "192.168.1.1:54321"
	rec := httptest.NewRecorder()
	pushCallbackHandler(deps)(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s, want 403", rec.Code, rec.Body.String())
	}
}

func TestPushCallback_IPAllowlistAccepts(t *testing.T) {
	store, _ := newCallbackTestStore(t)
	seedApproval(t, store, "ch-9")
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	deps := &pushCallbackDeps{
		Store:        store,
		AllowedCIDRs: []*net.IPNet{cidr},
		Logger:       quietLogger(),
	}
	req := httptest.NewRequest(http.MethodPost, "/push/approval/ch-9/approve", nil)
	req.RemoteAddr = "10.1.2.3:54321"
	rec := httptest.NewRecorder()
	pushCallbackHandler(deps)(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestParsePushCallbackPath_HappyAndFailure(t *testing.T) {
	for _, tc := range []struct {
		path    string
		wantID  string
		wantDec string
	}{
		{"/push/approval/abc/approve", "abc", "approve"},
		{"/push/approval/abc/deny", "abc", "deny"},
		{"/push/approval/abc/deny/", "abc", "deny"},
		{"/push/approval/", "", ""},
		{"/somewhere/else", "", ""},
	} {
		t.Run(tc.path, func(t *testing.T) {
			id, dec := parsePushCallbackPath(tc.path)
			if id != tc.wantID || dec != tc.wantDec {
				t.Errorf("got (%q, %q), want (%q, %q)", id, dec, tc.wantID, tc.wantDec)
			}
		})
	}
}

func TestBuildPushCallbackDeps_RejectsBadCIDR(t *testing.T) {
	store, _ := newCallbackTestStore(t)
	_, err := buildPushCallbackDeps(config.MFAPushCallbackConfig{
		AllowedCIDRs: []string{"not-a-cidr"},
	}, store, nil, quietLogger())
	if err == nil {
		t.Fatal("want error on bad CIDR")
	}
	if !strings.Contains(err.Error(), "not-a-cidr") {
		t.Errorf("error should mention the bad input: %v", err)
	}
}

// TestPushCallback_NotifyFiresOnSuccess proves the reference callback
// wakes the channel-notify fast path with the resolved id ONLY after a
// successful SetStatus — and never on a not-found error (no spurious
// wakeup for an id no Verify is parked on).
func TestPushCallback_NotifyFiresOnSuccess(t *testing.T) {
	store, _ := newCallbackTestStore(t)
	seedApproval(t, store, "ch-notify")

	var mu sync.Mutex
	var notified []string
	deps := &pushCallbackDeps{
		Store:  store,
		Logger: quietLogger(),
		Notify: func(id string) {
			mu.Lock()
			notified = append(notified, id)
			mu.Unlock()
		},
	}

	rec := callCallback(t, deps, "/push/approval/ch-notify/approve", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("approve status = %d body=%s", rec.Code, rec.Body.String())
	}

	// Unknown id → 404 and MUST NOT notify.
	rec = callCallback(t, deps, "/push/approval/ch-unknown/approve", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown-id status = %d, want 404", rec.Code)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(notified) != 1 || notified[0] != "ch-notify" {
		t.Fatalf("notified = %v, want exactly [ch-notify]", notified)
	}
}

// TestBuildMFA_PushChannelNotifySurfacesNotifier proves the channel_notify
// toggle controls whether buildMFA returns a live wakeup func: present
// when true, nil when false (so the callback wiring degrades to poll).
func TestBuildMFA_PushChannelNotifySurfacesNotifier(t *testing.T) {
	mk := func(channelNotify bool) func(string) {
		t.Helper()
		_, _, _, _, _, notify, err := buildMFA(config.MFAConfig{
			Enabled: true,
			Provider: config.MFAProviderConfig{
				Kind: "push",
				Push: config.MFAPushConfig{
					Backend:       "memory",
					Transport:     "log",
					ChannelNotify: channelNotify,
				},
			},
			Challenge: config.MFAChallengeConfig{Backend: "memory", TTL: time.Minute},
		}, nil, nil, quietLogger())
		if err != nil {
			t.Fatalf("buildMFA(channel_notify=%v): %v", channelNotify, err)
		}
		return notify
	}
	if mk(true) == nil {
		t.Error("channel_notify=true should surface a non-nil notifier")
	}
	if mk(false) != nil {
		t.Error("channel_notify=false should surface a nil notifier")
	}
}

// --- helpers ---

func decodeCallbackError(rec *httptest.ResponseRecorder) (map[string]string, error) {
	body, _ := io.ReadAll(rec.Body)
	out := map[string]string{}
	err := json.Unmarshal(body, &out)
	return out, err
}
