package ssotest

// B4-5 governance-connector evidence gate (G5 P2-parity leg,
// docs/campaigns/implementation-gate.md:77): the IdP side of the
// contract — an auth.* outbox with in-tx recording (login-failure
// post-commit being the only permitted class), drained by a relay
// reusing managed_relay.go, feeding the stock hash chain this tool
// exports. This file is the end-to-end proof; the CLI-side evidence
// (--dsn/--verify/--anchor exit codes) lives in
// cmd/sso-ctl/auditexport/main_test.go (test/ cannot import cmd/).
//
// A1  post-commit outbox durability before the relay runs + a single
//     linked chain event delivered after (idempotent, no duplicates).
// A2  exported bundle: contiguous=true, boundary/head vs store LastHash,
//     tamper -> verification failure.
// A3  --anchor enforcement: fresh checkpoint binds, stale/forged fail
//     (CLI-level tests in the module; here the notary head equality).
// A4  tenant_id + roles survive into the exported token_issued record.
// A5  G5 P2-parity leg green: the assertions above are the parity.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	tenantmemory "github.com/yangwb1123/snaplink/domains/tenant/memory"
	"github.com/yangwb1123/snaplink/infrastructure/auditgovernance"
	"github.com/yangwb1123/snaplink/infrastructure/auditoutbox"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/audit/auditexport"
	auditsqlite "github.com/yangwb1123/snaplink/platform/audit/sqlite"
	"github.com/yangwb1123/snaplink/platform/lifecycle/modules"
	"github.com/yangwb1123/snaplink/shared/core"
)

const (
	govTenantID = "tenant-acme"
	govHost     = "acme.sso.test"
	govClientID = "gov-client"
	govUserID   = "gov-user"
	govPassword = "correct horse battery staple"
)

// captureClient is the in-harness governance sink: it accepts every
// fact the relay publishes and records the deliveries for assertion.
type captureClient struct {
	mu   sync.Mutex
	got  []*commerce.OutboxEvent
	fail error
}

func (c *captureClient) Publish(_ context.Context, event *commerce.OutboxEvent) (auditgovernance.Receipt, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail != nil {
		return auditgovernance.Receipt{}, c.fail
	}
	c.got = append(c.got, event)
	return auditgovernance.Receipt{
		EventID: event.ID, TenantID: event.TenantID, Status: "accepted",
		AcceptedAt: time.Now().UTC(),
	}, nil
}

func (c *captureClient) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.got)
}

func (c *captureClient) first() *commerce.OutboxEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.got) == 0 {
		return nil
	}
	return c.got[0]
}

// newGovernanceHarness boots the B4-5 wiring on one temp sqlite file:
// audit sink + same-transaction outbox appender + chain-stamping
// recorder + a real server with a tenant domain, a tenant-scoped
// client, and an explicit org roster (admin membership) for the roles
// projection. reader is a second, appender-free handle on the same file
// (the durable-read assertion surface).
func newGovernanceHarness(t *testing.T) (
	reader *auditsqlite.Sink, outbox *auditoutbox.SQLiteOutboxStore, srv *httptest.Server,
) {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "governance.db")
	reader, err := auditsqlite.New(dsn)
	if err != nil {
		t.Fatalf("audit reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	outbox, err = auditoutbox.NewSQLiteOutboxStore(dsn)
	if err != nil {
		t.Fatalf("outbox store: %v", err)
	}
	t.Cleanup(func() { _ = outbox.Close() })
	wired, err := auditsqlite.New(dsn, auditsqlite.WithTxAppender(outbox))
	if err != nil {
		t.Fatalf("wired audit sink: %v", err)
	}
	t.Cleanup(func() { _ = wired.Close() })
	rec := audit.New(wired, audit.WithHashChain())

	tstore := tenantmemory.New()
	ctx := context.Background()
	if err := tstore.PutTenant(ctx, &tenant.Tenant{ID: govTenantID, Slug: "acme", Name: "Acme", Status: tenant.StatusActive}); err != nil {
		t.Fatalf("put tenant: %v", err)
	}
	if err := tstore.PutDomain(ctx, &tenant.Domain{Hostname: govHost, TenantID: govTenantID}); err != nil {
		t.Fatalf("put domain: %v", err)
	}
	users := defaultimpl.NewMemoryUserProvider()
	if err := users.CreateOrUpdate(ctx, &sso.User{ID: govUserID}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: govClientID, Secret: "gov-secret", Active: true, TenantID: govTenantID,
		AllowedAuthenticators: []string{"password"}, AllowedScopes: []string{"openid"}, TokenStrategy: "jwt",
	})
	roster := defaultimpl.NewMemoryTenantUserStore()
	if err := roster.Add(ctx, &core.TenantMembership{TenantID: govTenantID, UserID: govUserID, Role: core.TenantRoleAdmin}); err != nil {
		t.Fatalf("seed roster: %v", err)
	}
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p == govPassword {
				return &sso.AuthResult{UserID: govUserID}, nil
			}
			return nil, errors.New("bad password")
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("testkit-sso"),
		defaultimpl.WithEd25519TokenTTL(5*time.Minute),
	)
	srvOpts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithAuthenticator(pw),
		sso.WithTenantStore(tstore),
		sso.WithTenantUserStore(roster),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
		sso.WithAuditRecorder(rec),
	}
	srv = httptest.NewServer(sso.NewServer(srvOpts...).Handler())
	t.Cleanup(srv.Close)
	return reader, outbox, srv
}

// attemptLogin posts one /auth/login for the tenant domain and returns
// the HTTP status.
func attemptLogin(t *testing.T, srv *httptest.Server, password string) (int, map[string]any) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  govClientID,
		"credential": map[string]string{"username": govUserID, "password": password},
	})
	if err != nil {
		t.Fatalf("marshal login: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/auth/login", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Host = govHost
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// startRelay launches the governance relay exactly the way the
// deployment wires it: ManagedRelayFactory through the lifecycle
// manager. The relay polls the outbox; the capture client records
// deliveries. Cleanup cancels the module.
func startRelay(t *testing.T, outbox commerce.OutboxStore, client auditgovernance.Client) {
	t.Helper()
	factory := auditgovernance.ManagedRelayFactory{Build: func(
		_ context.Context, _ []byte, generation uint64,
	) ([]auditgovernance.ManagedRelay, error) {
		relay, err := auditgovernance.NewRelay(outbox, client, auditgovernance.RelayConfig{
			Owner: fmt.Sprintf("e2e-audit-g%d", generation),
		})
		if err != nil {
			return nil, err
		}
		return []auditgovernance.ManagedRelay{{Name: "audit-outbox", Relay: relay}}, nil
	}}
	manager, err := modules.New(
		[]modules.Definition{{ID: "audit-relay", Factory: factory}}, modules.Options{},
	)
	if err != nil {
		t.Fatalf("modules.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = manager.Close(context.Background())
	})
	if _, err := manager.Activate(ctx, "audit-relay", []byte(`{"revision":1}`)); err != nil {
		t.Fatalf("activate relay: %v", err)
	}
}

// attemptLoginScope is attemptLogin with an explicit scope parameter
// (refresh-token issuance is scoped: an unscoped login has nothing to
// persist).
func attemptLoginScope(t *testing.T, srv *httptest.Server, password, scope string) (int, map[string]any) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  govClientID,
		"scope":      []string{scope},
		"credential": map[string]string{"username": govUserID, "password": password},
	})
	if err != nil {
		t.Fatalf("marshal login: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/auth/login", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Host = govHost
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// exchangeRefreshToken performs one RFC 6749 refresh grant against
// /token (the same shape test/refresh_rotation_claims_test.go drives)
// and returns status + body.
func exchangeRefreshToken(t *testing.T, srv *httptest.Server, refresh string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refresh,
		"client_id":     govClientID,
		"client_secret": "gov-secret",
	})
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/token", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("refresh request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Host = govHost
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// waitFor polls cond until it returns true or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestGovernanceConnector_LoginFailureRelayAndExportChain is the A1/A2
// parity leg: a login failure records its outbox fact in the SAME
// transaction (durable before any relay runs), the managed relay
// delivers exactly one linked chain event, and the exported bundle is
// contiguous with boundary/head matching the store, verified against a
// signed notary checkpoint.
func TestGovernanceConnector_LoginFailureRelayAndExportChain(t *testing.T) {
	reader, outbox, srv := newGovernanceHarness(t)
	ctx := context.Background()

	// A failed login -> login_failure audit event + in-tx outbox fact.
	if status, _ := attemptLogin(t, srv, "wrong-password"); status != http.StatusUnauthorized {
		t.Fatalf("failed login status=%d, want 401", status)
	}
	chainEvents, err := reader.Query(ctx, audit.Query{})
	if err != nil || len(chainEvents) != 1 {
		t.Fatalf("chain events: %v %d", err, len(chainEvents))
	}
	event := chainEvents[0]
	if event.Type != audit.EventLoginFailure || event.TenantID != govTenantID {
		t.Fatalf("unexpected chain event: %+v", event)
	}

	// A1 durability BEFORE the relay: the fact is committed and
	// observable on a fresh handle, linked to the chain event.
	pending, err := outbox.Pending(ctx)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending facts before relay: %v %d (want 1 — in-tx commit)", err, len(pending))
	}
	fact := pending[0]
	if fact.TenantID != govTenantID || fact.Type != auditoutbox.FactEventType {
		t.Errorf("fact projection: %+v", fact)
	}
	if fact.Payload[auditoutbox.PayloadKeyAuditHash] != event.Hash {
		t.Errorf("fact audit_hash %q != chain event hash %q (linkage broken)",
			fact.Payload[auditoutbox.PayloadKeyAuditHash], event.Hash)
	}

	// A1 relay: managed_relay.go drains the outbox; exactly one linked
	// delivery, and a second pass delivers nothing (no duplicates).
	capture := &captureClient{}
	startRelay(t, outbox, capture)
	waitFor(t, "relay delivery", func() bool { return capture.count() == 1 })
	delivered := capture.first()
	if delivered.Payload[auditoutbox.PayloadKeyAuditHash] != event.Hash {
		t.Errorf("delivered fact audit_hash %q != chain event hash %q",
			delivered.Payload[auditoutbox.PayloadKeyAuditHash], event.Hash)
	}
	time.Sleep(300 * time.Millisecond) // allow any (wrong) duplicate pass
	if capture.count() != 1 {
		t.Errorf("relay delivered %d facts, want exactly 1 (single linked chain event)", capture.count())
	}

	// A2 export: contiguous full chain, boundary at genesis, head equal
	// to the store's LastHash, self-verification passing.
	bundle, err := auditexport.BuildExportBundle(ctx, reader, audit.Query{})
	if err != nil {
		t.Fatalf("build bundle: %v", err)
	}
	if !bundle.Contiguous {
		t.Error("full export must be contiguous=true")
	}
	if bundle.BoundaryPrevHash != audit.GenesisHash {
		t.Errorf("boundary prev hash: got %q want genesis", bundle.BoundaryPrevHash)
	}
	last, err := reader.LastHash(ctx)
	if err != nil {
		t.Fatalf("last hash: %v", err)
	}
	if bundle.HeadHash != last {
		t.Errorf("bundle head %q != store LastHash %q", bundle.HeadHash, last)
	}
	if err := auditexport.VerifyExportBundle(bundle); err != nil {
		t.Fatalf("bundle self-verify: %v", err)
	}

	// A3 notary: the genuine checkpoint attests exactly the exported
	// head (fresh), and a stale attestation of the PRE-event genesis
	// head fails head equality — the enforcement the CLI --anchor path
	// builds on.
	signer, err := audit.NewEd25519CheckpointSigner()
	if err != nil {
		t.Fatal(err)
	}
	notary := audit.NewNotary(reader, audit.NewMemoryCheckpointStore(), signer, time.Hour, nil, nil)
	fresh, err := notary.CheckpointNow(ctx)
	if err != nil {
		t.Fatalf("CheckpointNow: %v", err)
	}
	if fresh.Checkpoint.HeadHash != bundle.HeadHash {
		t.Errorf("fresh checkpoint head %q != bundle head %q", fresh.Checkpoint.HeadHash, bundle.HeadHash)
	}
	if err := audit.VerifyChainAgainstCheckpoint(bundle.Events, fresh); err != nil {
		t.Errorf("chain vs fresh checkpoint: %v", err)
	}
	stale := audit.SignedCheckpoint{
		Checkpoint: audit.Checkpoint{Sequence: 99, Timestamp: time.Now().UTC(), HeadHash: audit.GenesisHash},
	}
	sig, err := signer.Sign(mustJSON(t, stale.Checkpoint))
	if err != nil {
		t.Fatal(err)
	}
	stale.Signature, stale.SignerKey = sig, signer.PublicKey()
	if err := audit.VerifyChainAgainstCheckpoint(bundle.Events, &stale); err == nil {
		t.Error("stale checkpoint must fail chain verification")
	}

	// A2 tamper: a mutated event breaks verification.
	tampered := *bundle
	tampered.Events = append([]*audit.Event(nil), bundle.Events...)
	copy := *tampered.Events[0]
	copy.Reason = "tampered"
	tampered.Events[0] = &copy
	if err := auditexport.VerifyExportBundle(&tampered); err == nil {
		t.Error("tampered bundle must fail verification")
	}
}

// TestGovernanceConnector_TokenIssuedRolesProjection is the A4 parity
// leg: T-8(a) event detail (tenant_id/roles) survives into the exported
// token_issued record — roles ride as fail-open Metadata, never on the
// hash-chain wire shape.
func TestGovernanceConnector_TokenIssuedRolesProjection(t *testing.T) {
	reader, _, srv := newGovernanceHarness(t)
	ctx := context.Background()

	// /auth/login (direct mint) returns a refresh token once the refresh
	// store is wired and a scope is requested; the RFC 6749 refresh grant
	// then emits the token_issued event through the shared
	// recordTokenIssued funnel.
	status, loginBody := attemptLoginScope(t, srv, govPassword, "openid")
	if status != http.StatusOK {
		t.Fatalf("login status=%d, want 200", status)
	}
	refresh, _ := loginBody["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("no refresh_token in login response: %v", loginBody)
	}
	status, _ = exchangeRefreshToken(t, srv, refresh)
	if status != http.StatusOK {
		t.Fatalf("refresh grant status=%d, want 200", status)
	}
	bundle, err := auditexport.BuildExportBundle(ctx, reader, audit.Query{Type: audit.EventTokenIssued})
	if err != nil {
		t.Fatalf("build bundle: %v", err)
	}
	if bundle.EventCount != 1 {
		t.Fatalf("token_issued events: %d, want 1", bundle.EventCount)
	}
	issued := bundle.Events[0]
	if issued.Type != audit.EventTokenIssued {
		t.Fatalf("type: %+v", issued)
	}
	if issued.TenantID != govTenantID {
		t.Errorf("tenant_id: got %q want %q", issued.TenantID, govTenantID)
	}
	if issued.Metadata[core.KeyRoles] != string(core.TenantRoleAdmin) {
		t.Errorf("roles: got %q want %q (fail-open tenant-roster projection)",
			issued.Metadata[core.KeyRoles], core.TenantRoleAdmin)
	}
	if err := auditexport.VerifyExportBundle(bundle); err != nil {
		t.Errorf("exported token_issued bundle failed verify: %v", err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
