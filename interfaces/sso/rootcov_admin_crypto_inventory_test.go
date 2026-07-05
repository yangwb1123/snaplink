package sso_test

// rootcov_admin_crypto_inventory_test.go covers GET /api/v1/admin/crypto/keys
// and POST /api/v1/admin/crypto/keys/{id}/compromise (WithCryptoInventory):
// admin gating, filtering, the compliance audit trail, and the byte-identical
// default when the feature is unwired.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/lifecycle/cryptoinventory"
)

func cryptoKeysURL(base string) string { return base + "/api/v1/admin/crypto/keys" }
func cryptoKeyCompromiseURL(base, keyID string) string {
	return base + "/api/v1/admin/crypto/keys/" + keyID + "/compromise"
}

// cryptoInventoryFixture wires a real StaticSource (no mocks) behind an
// admin-gated server with an audit sink — everything the endpoints touch.
type cryptoInventoryFixture struct {
	env  *rcovAdminEnv
	sink *audit.MemorySink
}

func newCryptoInventoryFixture(t *testing.T) *cryptoInventoryFixture {
	t.Helper()
	src := &cryptoinventory.StaticSource{
		SourceName: "kms",
		Entries: []cryptoinventory.Entry{
			{KeyID: "kid-1", Algorithm: "EdDSA", Purpose: cryptoinventory.PurposeSign, Status: cryptoinventory.StatusActive, BackingStore: "memory"},
			{KeyID: "kms-key-1", Algorithm: "ECDSA_SHA_256", Purpose: cryptoinventory.PurposeSign, Status: cryptoinventory.StatusActive, BackingStore: "kms:awskms"},
		},
	}
	inv := cryptoinventory.NewMemoryInventory(src)
	sink := audit.NewMemorySink(50)
	env := rcovNewAdminServer(t,
		sso.WithCryptoInventory(inv),
		sso.WithAuditRecorder(audit.New(sink)),
	)
	return &cryptoInventoryFixture{env: env, sink: sink}
}

// TestRcovAdmin_CryptoKeysNotMountedWithoutInventory proves the byte-identical
// default: without WithCryptoInventory both routes 404 even for an authorized
// admin.
func TestRcovAdmin_CryptoKeysNotMountedWithoutInventory(t *testing.T) {
	t.Parallel()
	env := rcovNewAdminServer(t)
	status, _ := rcovDo(t, http.MethodGet, cryptoKeysURL(env.url), env.token, nil)
	if status != http.StatusNotFound {
		t.Fatalf("list without an inventory = %d, want 404", status)
	}
	status, _ = rcovDo(t, http.MethodPost, cryptoKeyCompromiseURL(env.url, "kid-1"), env.token, map[string]any{"reason": "x"})
	if status != http.StatusNotFound {
		t.Fatalf("compromise without an inventory = %d, want 404", status)
	}
}

// TestRcovAdmin_CryptoKeysRequiresAdminBearer proves the endpoint sits behind
// the same AdminMiddleware gate as every other /api/v1/admin/* route.
func TestRcovAdmin_CryptoKeysRequiresAdminBearer(t *testing.T) {
	t.Parallel()
	fx := newCryptoInventoryFixture(t)
	status, _ := rcovDo(t, http.MethodGet, cryptoKeysURL(fx.env.url), "", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("no-bearer list = %d, want 401", status)
	}
}

// TestRcovAdmin_CryptoKeysListAndFilter proves the catalog lists every
// registered key and honors the ?purpose=/?algorithm= filters.
func TestRcovAdmin_CryptoKeysListAndFilter(t *testing.T) {
	t.Parallel()
	fx := newCryptoInventoryFixture(t)

	status, out := rcovDo(t, http.MethodGet, cryptoKeysURL(fx.env.url), fx.env.token, nil)
	if status != http.StatusOK {
		t.Fatalf("list = %d body=%v", status, out)
	}
	keys, _ := out["keys"].([]any)
	if len(keys) != 2 {
		t.Fatalf("keys = %v, want 2 entries", keys)
	}

	status, out = rcovDo(t, http.MethodGet, cryptoKeysURL(fx.env.url)+"?algorithm=ECDSA_SHA_256", fx.env.token, nil)
	if status != http.StatusOK {
		t.Fatalf("filtered list = %d body=%v", status, out)
	}
	keys, _ = out["keys"].([]any)
	if len(keys) != 1 {
		t.Fatalf("filtered keys = %v, want 1 entry", keys)
	}
}

// TestRcovAdmin_CryptoKeyCompromiseSucceeds is the happy path: a valid
// compromise report marks the key compromised, records the compliance audit
// trail, and the subsequent list reflects the compromised status.
func TestRcovAdmin_CryptoKeyCompromiseSucceeds(t *testing.T) {
	t.Parallel()
	fx := newCryptoInventoryFixture(t)
	const reason = "incident-9002: kid-1 exposed in a crash dump"

	status, out := rcovDo(t, http.MethodPost, cryptoKeyCompromiseURL(fx.env.url, "kid-1"), fx.env.token, map[string]any{"reason": reason})
	if status != http.StatusOK {
		t.Fatalf("compromise = %d body=%v", status, out)
	}
	key, _ := out["key"].(map[string]any)
	if key["status"] != "compromised" {
		t.Errorf("status = %v, want compromised", key["status"])
	}

	evts, err := fx.sink.Query(context.Background(), audit.Query{Type: audit.EventAdminCryptoKeyCompromised})
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
	if e.Metadata["crypto_key_id"] != "kid-1" || e.Metadata["crypto_key_reason"] != reason {
		t.Errorf("audit metadata id/reason = %q/%q", e.Metadata["crypto_key_id"], e.Metadata["crypto_key_reason"])
	}

	status, out = rcovDo(t, http.MethodGet, cryptoKeysURL(fx.env.url)+"?status=compromised", fx.env.token, nil)
	if status != http.StatusOK {
		t.Fatalf("post-compromise list = %d body=%v", status, out)
	}
	keys, _ := out["keys"].([]any)
	if len(keys) != 1 {
		t.Fatalf("post-compromise compromised-status keys = %v, want 1", keys)
	}
}

// TestRcovAdmin_CryptoKeyCompromiseReasonRequired rejects a blank reason — an
// unexplained compromise is itself an audit finding.
func TestRcovAdmin_CryptoKeyCompromiseReasonRequired(t *testing.T) {
	t.Parallel()
	fx := newCryptoInventoryFixture(t)
	status, out := rcovDo(t, http.MethodPost, cryptoKeyCompromiseURL(fx.env.url, "kid-1"), fx.env.token, map[string]any{"reason": "  "})
	if status != http.StatusBadRequest || out["error"] != "compromise_reason_required" {
		t.Fatalf("blank-reason compromise = %d %v, want 400 compromise_reason_required", status, out)
	}
}

// TestRcovAdmin_CryptoKeyCompromiseUnknownKey 404s a key id no Source knows
// about (anti-enumeration is not a concern here — the caller is an
// authorized admin, mirroring the credential-compromise endpoint's own
// unknown-type 404).
func TestRcovAdmin_CryptoKeyCompromiseUnknownKey(t *testing.T) {
	t.Parallel()
	fx := newCryptoInventoryFixture(t)
	status, _ := rcovDo(t, http.MethodPost, cryptoKeyCompromiseURL(fx.env.url, "does-not-exist"), fx.env.token, map[string]any{"reason": "x"})
	if status != http.StatusNotFound {
		t.Fatalf("unknown-key compromise = %d, want 404", status)
	}
}

// TestRcovAdmin_CryptoKeyCompromiseNoStoreHeaders proves the compromise
// endpoint stamps no-store cache headers (it mutates state — never
// cacheable), mirroring the credential-compromise endpoint's own check.
func TestRcovAdmin_CryptoKeyCompromiseNoStoreHeaders(t *testing.T) {
	t.Parallel()
	fx := newCryptoInventoryFixture(t)
	body, _ := json.Marshal(map[string]any{"reason": "cache-header-check"})
	req, _ := http.NewRequest(http.MethodPost, cryptoKeyCompromiseURL(fx.env.url, "kid-1"), bytes.NewReader(body))
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
