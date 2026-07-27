package sso_test

// rootcov_admin_credential_compromise_test.go covers
// POST /api/v1/admin/credentials/{type}/compromise — the emergency
// compromise-response endpoint (WithCredentialCompromise): admin gating,
// no-secret-leak, the compliance audit trail, and the dependent-party notifier.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/defaultjwe"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/rotation"
	"github.com/yangwb1123/snaplink/shared/core/corecredential"
)

// compromiseFixture wires a real rotating JWE decrypter (a CompromiseRotator)
// plus a plain, compromise-UNsupported stubRotator into one scheduler, behind an
// admin-gated server with a recording notifier + audit sink — everything the
// endpoint's fan-out touches, with no mocks (real Memory* impls per convention).
type compromiseFixture struct {
	env      *rcovAdminEnv
	sink     *audit.MemorySink
	notifier *defaultimpl.MemoryDependentPartyNotifier
	store    *defaultimpl.MemoryCredentialStatusStore
}

func newCompromiseFixture(t *testing.T) *compromiseFixture {
	t.Helper()
	jwe, err := defaultjwe.NewRotatingJWEDecrypter(nil, "jwe-enc", 2048, time.Hour)
	if err != nil {
		t.Fatalf("new rotating jwe: %v", err)
	}
	reg := rotation.NewRegistry()
	if err := reg.Register(jwe, time.Hour); err != nil {
		t.Fatalf("register jwe rotator: %v", err)
	}
	// A plain CredentialRotator (no RotateCompromised) to exercise the 400 path.
	if err := reg.Register(stubRotator{overlap: time.Minute}, time.Hour); err != nil {
		t.Fatalf("register stub rotator: %v", err)
	}
	store := defaultimpl.NewMemoryCredentialStatusStore()
	notifier := defaultimpl.NewMemoryDependentPartyNotifier()
	sched := rotation.NewScheduler(reg,
		rotation.WithStatusStore(store), rotation.WithNotifier(notifier))
	sink := audit.NewMemorySink(50)
	env := rcovNewAdminServer(t,
		sso.WithCredentialRotation(reg),
		sso.WithCredentialCompromise(sched),
		sso.WithAuditRecorder(audit.New(sink)),
	)
	return &compromiseFixture{env: env, sink: sink, notifier: notifier, store: store}
}

func compromiseURL(base, credType string) string {
	return base + "/api/v1/admin/credentials/" + credType + "/compromise"
}

// TestRcovAdmin_CompromiseNotMountedWithoutScheduler proves the byte-identical
// default: without WithCredentialCompromise the route 404s even for an
// authorized admin.
func TestRcovAdmin_CompromiseNotMountedWithoutScheduler(t *testing.T) {
	t.Parallel()
	env := rcovNewAdminServer(t)
	status, _ := rcovDo(t, http.MethodPost, compromiseURL(env.url, "jwe_decryption"), env.token, map[string]any{"reason": "x"})
	if status != http.StatusNotFound {
		t.Fatalf("compromise without a scheduler = %d, want 404", status)
	}
}

// TestRcovAdmin_CompromiseRequiresAdminBearer proves the endpoint sits behind
// the same AdminMiddleware gate as every other /api/v1/admin/* route.
func TestRcovAdmin_CompromiseRequiresAdminBearer(t *testing.T) {
	t.Parallel()
	fx := newCompromiseFixture(t)
	status, _ := rcovDo(t, http.MethodPost, compromiseURL(fx.env.url, "jwe_decryption"), "", map[string]any{"reason": "x"})
	if status != http.StatusUnauthorized {
		t.Fatalf("no-bearer compromise = %d, want 401", status)
	}
}

// TestRcovAdmin_CompromiseSucceeds is the happy path: a valid compromise returns
// the NEW version's governance metadata (never secret material), fires the
// notifier for the affected dependents, records the compliance audit trail, and
// persists the leaked+fresh statuses.
func TestRcovAdmin_CompromiseSucceeds(t *testing.T) {
	t.Parallel()
	fx := newCompromiseFixture(t)
	const reason = "incident-9001: enc key exposed in logs"

	status, out := rcovDo(t, http.MethodPost, compromiseURL(fx.env.url, "jwe_decryption"), fx.env.token, map[string]any{"reason": reason})
	if status != http.StatusOK {
		t.Fatalf("compromise = %d body=%v", status, out)
	}
	assertNoSecretLeak(t, out)
	assertNotifierFired(t, fx.notifier)
	assertAuditTrail(t, fx.sink, reason)
	assertStatusStore(t, fx.store)
}

func assertNoSecretLeak(t *testing.T, out map[string]any) {
	t.Helper()
	cred, _ := out["credential"].(map[string]any)
	if cred == nil {
		t.Fatalf("no credential in response: %v", out)
	}
	if cred["type"] != "jwe_decryption" {
		t.Errorf("type = %v, want jwe_decryption", cred["type"])
	}
	if v, _ := cred["version"].(float64); v != 2 {
		t.Errorf("version = %v, want 2 (fresh version after compromise)", cred["version"])
	}
	if cred["status"] != "active" {
		t.Errorf("status = %v, want active", cred["status"])
	}
	allowed := map[string]bool{"id": true, "type": true, "version": true, "status": true, "created_at": true, "not_after": true, "algorithm": true}
	for k := range cred {
		if !allowed[k] {
			t.Errorf("unexpected field %q in compromise response (governance-only surface): %v", k, cred)
		}
	}
}

func assertNotifierFired(t *testing.T, notifier *defaultimpl.MemoryDependentPartyNotifier) {
	t.Helper()
	notices := notifier.Notices()
	if len(notices) != 1 {
		t.Fatalf("notices = %d, want 1", len(notices))
	}
	n := notices[0]
	if !n.Compromised || n.Type != corecredential.CredentialTypeJWEDecryption {
		t.Errorf("notice = compromised %v type %q, want true/jwe_decryption", n.Compromised, n.Type)
	}
	if len(n.Dependents) != 1 || n.Dependents[0] != corecredential.DependencyJWKS {
		t.Errorf("notice.Dependents = %v, want [jwks]", n.Dependents)
	}
}

func assertAuditTrail(t *testing.T, sink *audit.MemorySink, reason string) {
	t.Helper()
	evts, err := sink.Query(context.Background(), audit.Query{Type: audit.EventAdminCredentialCompromised})
	if err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if len(evts) != 1 {
		t.Fatalf("compromise audit events = %d, want 1", len(evts))
	}
	e := evts[0]
	if e.ActorID == "" {
		t.Error("audit event has no ActorID (who)")
	}
	md := e.Metadata
	if md["credential_type"] != "jwe_decryption" || md["credential_reason"] != reason {
		t.Errorf("audit metadata type/reason = %q/%q", md["credential_type"], md["credential_reason"])
	}
	if md["credential_old_version"] != "1" || md["credential_new_version"] != "2" {
		t.Errorf("audit version chain = old %q new %q, want 1 -> 2", md["credential_old_version"], md["credential_new_version"])
	}
}

func assertStatusStore(t *testing.T, store *defaultimpl.MemoryCredentialStatusStore) {
	t.Helper()
	rows, err := store.ListByType(context.Background(), corecredential.CredentialTypeJWEDecryption)
	if err != nil {
		t.Fatalf("status store list: %v", err)
	}
	byVersion := map[int]corecredential.CredentialStatus{}
	for _, m := range rows {
		byVersion[m.Version] = m.Status
	}
	if byVersion[1] != corecredential.CredentialStatusCompromised {
		t.Errorf("v1 status = %q, want compromised", byVersion[1])
	}
	if byVersion[2] != corecredential.CredentialStatusActive {
		t.Errorf("v2 status = %q, want active", byVersion[2])
	}
}

// TestRcovAdmin_CompromiseReasonRequired rejects a blank reason — an unexplained
// compromise is itself an audit finding.
func TestRcovAdmin_CompromiseReasonRequired(t *testing.T) {
	t.Parallel()
	fx := newCompromiseFixture(t)
	status, out := rcovDo(t, http.MethodPost, compromiseURL(fx.env.url, "jwe_decryption"), fx.env.token, map[string]any{"reason": "  "})
	if status != http.StatusBadRequest || out["error"] != "compromise_reason_required" {
		t.Fatalf("blank-reason compromise = %d %v, want 400 compromise_reason_required", status, out)
	}
}

// TestRcovAdmin_CompromiseUnknownType 404s an unregistered credential class.
func TestRcovAdmin_CompromiseUnknownType(t *testing.T) {
	t.Parallel()
	fx := newCompromiseFixture(t)
	status, _ := rcovDo(t, http.MethodPost, compromiseURL(fx.env.url, "not_a_real_credential"), fx.env.token, map[string]any{"reason": "x"})
	if status != http.StatusNotFound {
		t.Fatalf("unknown-type compromise = %d, want 404", status)
	}
}

// TestRcovAdmin_CompromiseUnsupported 400s a class whose rotator cannot instantly
// retire its secret (implements CredentialRotator but not CompromiseRotator).
func TestRcovAdmin_CompromiseUnsupported(t *testing.T) {
	t.Parallel()
	fx := newCompromiseFixture(t)
	status, out := rcovDo(t, http.MethodPost, compromiseURL(fx.env.url, "test_stub_cred"), fx.env.token, map[string]any{"reason": "x"})
	if status != http.StatusBadRequest || out["error"] != "credential_compromise_unsupported" {
		t.Fatalf("unsupported compromise = %d %v, want 400 credential_compromise_unsupported", status, out)
	}
}

// TestRcovAdmin_CompromiseNoStoreHeaders proves the credential endpoint stamps
// no-store cache headers (it triggers secret rotation — never cacheable).
func TestRcovAdmin_CompromiseNoStoreHeaders(t *testing.T) {
	t.Parallel()
	fx := newCompromiseFixture(t)
	body, _ := json.Marshal(map[string]any{"reason": "cache-header-check"})
	req, _ := http.NewRequest(http.MethodPost, compromiseURL(fx.env.url, "jwe_decryption"), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+fx.env.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}
