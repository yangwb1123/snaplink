package ssotest

// Import-governance acceptance mapping (AC1-AC5 of
// docs/architect-analysis/cmd-sso-ctl-importcmd-governance-outbox-requirements.md),
// driven through the store seam the CLI calls: sqlite.UserProvider.ImportUser
// (sqlite) / tenantcommerce.ImportUserTx (postgres, env-gated in the
// tenantcommerce package). test/ cannot import cmd/, so the CLI wiring itself
// is proven in cmd/sso-ctl/importcmd/main_test.go (AC5); here the EXACT
// functions the CLI calls are exercised end to end:
//
//	AC1  N users -> exactly N tenant-tied events, atomic (user, event) pairs.
//	AC2  a failing row rolls back its own pair; neighbors persist.
//	AC3  drain via auditgovernance.Relay + ManagedRelayFactory + modules
//	     manager + captureClient (the startRelay harness), once, no dupes.
//	AC4  /auth/login + /token byte-identical oracle for a skipped identity
//	     vs an unknown one (partially-imported user must never surface as a
//	     distinguishable error — T-8 discipline link).
//
// Failure modes pinned here: crash rerun (idempotent), concurrent sqlite
// writers (server + CLI on one file), recipient rejection (dead-letter +
// replay safety net). The payload-spec conflict is pinned on both backends:
// sqlite keeps the old row (documented asymmetry, unit test in the sqlite
// package), postgres surfaces ErrIdempotencyConflict (integration test in
// the tenantcommerce package).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	sqlitestores "github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"golang.org/x/crypto/bcrypt"
)

const importTenantID = "tenant-import"

// importEvent mirrors importcmd.newImportFact — the deterministic
// "import:<tenant>:<userID>" ID/key, bounded redacted payload, canonical
// digest. The event construction is importcmd policy (proven in-package);
// this file drives the store pair-write exactly as the CLI calls it.
func importEvent(tenantID string, u *sso.User) *commerce.OutboxEvent {
	now := time.Now().UTC()
	payload := map[string]string{"user_id": u.ID, "provider": u.Provider}
	key := "import:" + tenantID + ":" + u.ID
	return &commerce.OutboxEvent{
		ID: key, TenantID: tenantID, Type: "snaplink.audit.user.import",
		AggregateType: "user", AggregateID: u.ID, AggregateVersion: 1,
		IdempotencyKey: key, OccurredAt: now, Payload: payload,
		PayloadDigest: importDigest(payload), Status: commerce.OutboxPending, CreatedAt: now,
	}
}

// importDigest is the canonical sha256 hex digest (json.Marshal sorts map
// keys) — identical to importcmd.digestPayload.
func importDigest(payload map[string]string) string {
	encoded, _ := json.Marshal(payload)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// newImportDB opens a REAL file-backed sqlite user provider on a fresh
// temp file (production-style WAL + busy_timeout DSN) and ensures the
// audit_outbox schema exactly the way the CLI's openDB does. It returns
// the provider and the DSN (for the outbox store's own pool).
func newImportDB(t *testing.T) (*sqlitestores.UserProvider, string) {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "import.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	p, err := sqlitestores.NewUserProvider(dsn)
	if err != nil {
		t.Fatalf("NewUserProvider: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	if err := auditoutbox.Migrate(context.Background(), p.DB()); err != nil {
		t.Fatalf("migrate audit_outbox: %v", err)
	}
	return p, dsn
}

// importOutbox opens the outbox store on its own pool (the CLI never does
// this; the relay worker does — the drain seam).
func importOutbox(t *testing.T, dsn string) *auditoutbox.SQLiteOutboxStore {
	t.Helper()
	store, err := auditoutbox.NewSQLiteOutboxStore(dsn)
	if err != nil {
		t.Fatalf("outbox store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// importUsers drives the store pair-write for the given users (the exact
// per-row call runImport makes) and returns any first error.
func importUsers(ctx context.Context, p *sqlitestores.UserProvider, tenantID string, users ...*sso.User) error {
	for _, u := range users {
		if err := p.ImportUser(ctx, u, importEvent(tenantID, u)); err != nil {
			return err
		}
	}
	return nil
}

// AC1 — importing N users through the store seam the CLI calls yields
// exactly N governance events in the SAME sqlite file: every event's
// TenantID is the --tenant value, every AggregateID is in the imported
// set, and the pairing invariant holds (no user without an event, no
// event without a user). Per-row atomicity interpretation pinned: each
// (user, event) pair commits in one transaction.
func TestImportGovernance_AC1_NUsersExactlyNEventsAtomicPairs(t *testing.T) {
	ctx := context.Background()
	p, dsn := newImportDB(t)
	users := []*sso.User{
		{ID: "csv:a@x.z", Provider: "csv", Email: "a@x.z"},
		{ID: "csv:b@x.z", Provider: "csv", Email: "b@x.z"},
		{ID: "auth0:00u9", Provider: "auth0", Email: "c@x.z"},
	}
	if err := importUsers(ctx, p, importTenantID, users...); err != nil {
		t.Fatalf("ImportUser: %v", err)
	}

	// Durability BEFORE any relay: a fresh handle on the same file sees
	// the committed rows.
	events, err := importOutbox(t, dsn).Pending(ctx)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(events) != len(users) {
		t.Fatalf("events = %d, want %d (exactly one per user)", len(events), len(users))
	}
	seen := map[string]bool{}
	for _, e := range events {
		if e.TenantID != importTenantID {
			t.Errorf("event tenant = %q, want the --tenant value %q", e.TenantID, importTenantID)
		}
		if e.Type != "snaplink.audit.user.import" {
			t.Errorf("event type = %q, want snaplink.audit.user.import", e.Type)
		}
		if e.Payload["user_id"] != e.AggregateID || e.Payload["email"] != "" {
			t.Errorf("event payload not the bounded redacted projection: %+v", e.Payload)
		}
		if err := e.Validate(); err != nil {
			t.Errorf("stored event invalid: %v", err)
		}
		seen[e.AggregateID] = true
	}
	for _, u := range users {
		if !seen[u.ID] {
			t.Errorf("no event for imported user %q", u.ID)
		}
	}

	// Pairing invariant: users table has exactly the imported rows, and
	// the event count matches the user count (no orphan on either side).
	all, err := p.List(ctx)
	if err != nil || len(all) != len(users) {
		t.Fatalf("user rows = %d (%v), want %d", len(all), err, len(users))
	}
	for _, u := range all {
		if !seen[u.ID] {
			t.Errorf("user %q has no event — orphan user", u.ID)
		}
	}
}

// AC2 — a row that fails mid-pair (its event fails validation AFTER the
// user upsert succeeded inside the transaction) rolls back BOTH rows:
// zero orphan users, zero orphan events; preceding and following good
// pairs persist.
func TestImportGovernance_AC2_FailingRowRollsBackPair(t *testing.T) {
	ctx := context.Background()
	p, dsn := newImportDB(t)

	good1 := &sso.User{ID: "csv:good1@x.z", Provider: "csv", Email: "good1@x.z"}
	good2 := &sso.User{ID: "csv:good2@x.z", Provider: "csv", Email: "good2@x.z"}
	bad := &sso.User{ID: "csv:skipped@x.z", Provider: "csv", Email: "skipped@x.z"}

	if err := p.ImportUser(ctx, good1, importEvent(importTenantID, good1)); err != nil {
		t.Fatal(err)
	}
	broken := importEvent(importTenantID, bad)
	broken.TenantID = "" // fails OutboxEvent.Validate AFTER the user upsert
	if err := p.ImportUser(ctx, bad, broken); err == nil {
		t.Fatal("ImportUser with an invalid event must error")
	}
	if err := p.ImportUser(ctx, good2, importEvent(importTenantID, good2)); err != nil {
		t.Fatal(err)
	}

	// The bad pair left NOTHING behind.
	if _, err := p.GetByID(ctx, bad.ID); !errors.Is(err, sso.ErrNoSuchUser) {
		t.Errorf("bad user row survived the rollback: %v", err)
	}
	events, err := importOutbox(t, dsn).Pending(ctx)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2 (good pairs only)", len(events))
	}
	for _, e := range events {
		if e.AggregateID == bad.ID {
			t.Errorf("orphan event for the rolled-back user: %+v", e)
		}
	}
	// Good neighbors persist with their events.
	for _, id := range []string{good1.ID, good2.ID} {
		if _, err := p.GetByID(ctx, id); err != nil {
			t.Errorf("good user %q missing: %v", id, err)
		}
	}
}

// AC3 — the AC1 events drain through the standard relay machinery: the
// same ManagedRelayFactory + modules-manager + captureClient harness the
// auditoutbox governance test uses (startRelay). All N events are
// delivered exactly once, leave pending, and a second drain run claims
// nothing.
func TestImportGovernance_AC3_RelayDrainsManagedLifecycle(t *testing.T) {
	ctx := context.Background()
	p, dsn := newImportDB(t)
	users := []*sso.User{
		{ID: "csv:u1@x.z", Provider: "csv", Email: "u1@x.z"},
		{ID: "csv:u2@x.z", Provider: "csv", Email: "u2@x.z"},
		{ID: "csv:u3@x.z", Provider: "csv", Email: "u3@x.z"},
	}
	if err := importUsers(ctx, p, importTenantID, users...); err != nil {
		t.Fatalf("ImportUser: %v", err)
	}
	outbox := importOutbox(t, dsn)

	capture := &captureClient{}
	startRelay(t, outbox, capture) // ManagedRelayFactory + modules manager
	waitFor(t, "relay delivery of all import events", func() bool {
		return capture.count() == len(users)
	})
	time.Sleep(300 * time.Millisecond) // allow any (wrong) duplicate pass
	if capture.count() != len(users) {
		t.Errorf("relay delivered %d events, want exactly %d (no duplicates)",
			capture.count(), len(users))
	}
	for _, e := range capture.got {
		if e.Type != "snaplink.audit.user.import" || e.TenantID != importTenantID {
			t.Errorf("delivered event wrong: %+v", e)
		}
	}

	// Rows left pending: the relay completed them.
	if pending, err := outbox.Pending(ctx); err != nil || len(pending) != 0 {
		t.Errorf("pending after drain = %d (%v), want 0", len(pending), err)
	}
	// A second drain run (fresh owner) delivers nothing new.
	second, err := auditgovernance.NewRelay(outbox, capture, auditgovernance.RelayConfig{
		Owner: "e2e-import-second-pass",
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := second.RunOnce(ctx)
	if err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}
	if res.Claimed != 0 || res.Delivered != 0 {
		t.Errorf("second drain claimed=%d delivered=%d, want 0/0", res.Claimed, res.Delivered)
	}
}

// AC4 — /token oracle link to T-8 discipline: after a partially failed
// import (AC2 scenario), the SKIPPED identity is byte-identical at the
// credential endpoints to a NEVER-SEEN identity. The password path (where
// the cost-matched dummy-bcrypt oracle lives) is /auth/login; /token is
// identity-agnostic (password is not a token grant) and must be
// byte-identical too — a partially-imported user must never surface as a
// distinguishable error anywhere on the credential surface.
func TestImportGovernance_AC4_TokenOracleByteIdentical(t *testing.T) {
	ctx := context.Background()
	p, _ := newImportDB(t)

	// Partially failed import: ok1 lands with its bcrypt hash (imported
	// users must actually be able to log in through this server), the
	// skipped identity's pair rolled back.
	const okPassword = "correct horse battery staple"
	hash, err := bcrypt.GenerateFromPassword([]byte(okPassword), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	ok1 := &sso.User{
		ID: "csv:ok1@x.z", Provider: "csv", Email: "ok1@x.z",
		Attributes: map[string]string{
			authenticators.AttrPasswordHash:       string(hash),
			authenticators.AttrPasswordHashFormat: authenticators.HashFormatBcrypt,
		},
	}
	skipped := &sso.User{ID: "csv:skipped@x.z", Provider: "csv", Email: "skipped@x.z"}
	if err := p.ImportUser(ctx, ok1, importEvent(importTenantID, ok1)); err != nil {
		t.Fatal(err)
	}
	broken := importEvent(importTenantID, skipped)
	broken.TenantID = ""
	if err := p.ImportUser(ctx, skipped, broken); err == nil {
		t.Fatal("expected the skipped pair to fail")
	}
	neverSeen := "csv:never-seen@x.z"

	// Real server on the SAME sqlite file the import wrote, with the
	// imported-hash verifier the server build wires for
	// authenticators.password.imported_hash_login (StoredHashVerifier over
	// the user provider + cost-matched dummy; LazyRehash wrapper omitted —
	// the oracle under test is the miss path).
	srv := newImportServer(t, p)
	host := "import-ac4.sso.test"
	clientID := "import-ac4-client"
	const wrongPassword = "wrong password whatever"

	// /auth/login: skipped identity vs never-seen identity, byte-identical
	// 401 (cost-matched dummy-bcrypt miss path — same error class/body).
	statusA, bodyA := postLoginRaw(t, srv, host, clientID, skipped.ID, wrongPassword)
	statusB, bodyB := postLoginRaw(t, srv, host, clientID, neverSeen, wrongPassword)
	if statusA != http.StatusUnauthorized || statusB != http.StatusUnauthorized {
		t.Fatalf("login statuses = %d/%d, want 401/401", statusA, statusB)
	}
	if !bytes.Equal(bodyA, bodyB) {
		t.Errorf("skipped identity login body != unknown identity body:\nskipped: %s\nunknown: %s", bodyA, bodyB)
	}

	// /token: password-shaped request for both identities — byte-identical
	// 400 unsupported_grant_type (the token endpoint never consults the
	// user store; the pin is that it stays indistinguishable).
	statusC, bodyC := postTokenRaw(t, srv, host, clientID, skipped.ID)
	statusD, bodyD := postTokenRaw(t, srv, host, clientID, neverSeen)
	if statusC != http.StatusBadRequest || statusD != http.StatusBadRequest {
		t.Fatalf("token statuses = %d/%d, want 400/400", statusC, statusD)
	}
	if !bytes.Equal(bodyC, bodyD) {
		t.Errorf("skipped identity /token body != unknown identity body:\nskipped: %s\nunknown: %s", bodyC, bodyD)
	}

	// Sanity: the harness is real — the successfully imported user CAN log
	// in through the same server (proves the oracle comparison sits on a
	// live credential path, not a stub).
	statusOK, bodyOK := postLoginRaw(t, srv, host, clientID, ok1.ID, okPassword)
	if statusOK != http.StatusOK {
		t.Errorf("imported user login status = %d, want 200: %s", statusOK, bodyOK)
	}
}

// newImportServer builds the AC4 server on the given (real sqlite) user
// provider: password authenticator backed by StoredHashVerifier (the
// imported-hash seam), memory client store, tenant domain routing, token
// issuance — the minimal REAL stack the auditoutbox harness uses.
func newImportServer(t *testing.T, users *sqlitestores.UserProvider) *httptest.Server {
	t.Helper()
	ctx := context.Background()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "import-ac4-client", Secret: "import-secret", Active: true,
		AllowedAuthenticators: []string{"password"},
		AllowedScopes:         []string{"openid"}, TokenStrategy: "jwt",
	})
	tstore := tenantmemory.New()
	if err := tstore.PutTenant(ctx, &tenant.Tenant{ID: importTenantID, Slug: "import", Name: "Import", Status: tenant.StatusActive}); err != nil {
		t.Fatal(err)
	}
	if err := tstore.PutDomain(ctx, &tenant.Domain{Hostname: "import-ac4.sso.test", TenantID: importTenantID}); err != nil {
		t.Fatal(err)
	}
	verifier := authenticators.NewStoredHashVerifier(users,
		authenticators.WithHasher(authenticators.NewBcryptHasher(bcrypt.DefaultCost)))
	pw := authenticators.NewPasswordAuthenticator(verifier)
	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("testkit-import"),
		defaultimpl.WithEd25519TokenTTL(5*time.Minute),
	)
	srv := httptest.NewServer(sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithAuthenticator(pw),
		sso.WithTenantStore(tstore),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
	).Handler())
	t.Cleanup(srv.Close)
	return srv
}

// postLoginRaw posts one password login to /auth/login and returns the
// RAW status + body bytes (the byte-identical assertion surface).
func postLoginRaw(t *testing.T, srv *httptest.Server, host, clientID, username, password string) (int, []byte) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  clientID,
		"credential": map[string]string{"username": username, "password": password},
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/auth/login", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// postTokenRaw posts a password-shaped grant to /token and returns RAW
// status + body bytes.
func postTokenRaw(t *testing.T, srv *httptest.Server, host, clientID, username string) (int, []byte) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"grant_type":    "password",
		"client_id":     clientID,
		"client_secret": "import-secret",
		"username":      username,
		"password":      "wrong password whatever",
	})
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/token", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// Failure mode: crash rerun. A crash mid-import (the in-flight pair never
// commits) leaves nothing behind; rerunning the FULL file is idempotent —
// committed pairs no-op on their deterministic IDs, the missing pair
// lands, and no event is ever duplicated.
func TestImportGovernance_CrashRerunIsIdempotent(t *testing.T) {
	ctx := context.Background()
	p, dsn := newImportDB(t)
	file := []*sso.User{
		{ID: "csv:a@x.z", Provider: "csv", Email: "a@x.z"},
		{ID: "csv:b@x.z", Provider: "csv", Email: "b@x.z"},
	}
	if err := importUsers(ctx, p, importTenantID, file...); err != nil {
		t.Fatal(err)
	}

	// Simulate the crash: begin the pair tx for user C, write both rows,
	// then abandon WITHOUT commit (the process died before COMMIT).
	c := &sso.User{ID: "csv:c@x.z", Provider: "csv", Email: "c@x.z"}
	tx, err := p.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.CreateOrUpdateTx(ctx, tx, c); err != nil {
		t.Fatal(err)
	}
	if err := auditoutbox.InsertEventTx(ctx, tx, importEvent(importTenantID, c)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil { // crash: no COMMIT
		t.Fatal(err)
	}
	if _, err := p.GetByID(ctx, c.ID); !errors.Is(err, sso.ErrNoSuchUser) {
		t.Fatalf("in-flight pair survived the crash: %v", err)
	}

	// Rerun the full file (now including C): A/B no-op, C lands.
	file = append(file, c)
	if err := importUsers(ctx, p, importTenantID, file...); err != nil {
		t.Fatalf("rerun after crash: %v", err)
	}
	all, _ := p.List(ctx)
	if len(all) != len(file) {
		t.Errorf("users after rerun = %d, want %d", len(all), len(file))
	}
	events, err := importOutbox(t, dsn).Pending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != len(file) {
		t.Errorf("events after rerun = %d, want %d (no duplicates, exactly one per user)",
			len(events), len(file))
	}
	// Every rerun event ID is the deterministic key — the same identity a
	// fresh run would produce (idempotency identity stable across runs).
	for _, e := range events {
		want := "import:" + importTenantID + ":" + e.AggregateID
		if e.ID != want || e.IdempotencyKey != want {
			t.Errorf("event identity not deterministic: id=%q key=%q want=%q", e.ID, e.IdempotencyKey, want)
		}
	}
}

// Failure mode: concurrent sqlite writers. The CLI (ImportUser pair-writes)
// and a server-style writer (CreateOrUpdate on a second pool, the shape a
// running sso-server holds) write the same file concurrently; per-row
// transactions + WAL + busy_timeout serialize them — no error, no
// corruption, and exactly the imported users carry events.
func TestImportGovernance_ConcurrentSqliteWriters(t *testing.T) {
	ctx := context.Background()
	p, dsn := newImportDB(t)

	serverPool, err := sqlitestores.NewUserProvider(dsn) // second pool: the server
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverPool.Close() })

	const n = 5
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() { // CLI: per-row pair-writes
		defer wg.Done()
		for i := 0; i < n; i++ {
			u := &sso.User{ID: fmt.Sprintf("csv:cli%d@x.z", i), Provider: "csv", Email: fmt.Sprintf("cli%d@x.z", i)}
			if err := p.ImportUser(ctx, u, importEvent(importTenantID, u)); err != nil {
				errs <- fmt.Errorf("ImportUser: %w", err)
				return
			}
		}
	}()
	go func() { // server: plain upserts, no events
		defer wg.Done()
		for i := 0; i < n; i++ {
			u := &sso.User{ID: fmt.Sprintf("csv:srv%d@x.z", i), Provider: "csv", Email: fmt.Sprintf("srv%d@x.z", i)}
			if err := serverPool.CreateOrUpdate(ctx, u); err != nil {
				errs <- fmt.Errorf("CreateOrUpdate: %w", err)
				return
			}
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent write failed: %v", err)
	}

	// All ten rows landed; exactly the CLI's five carry events.
	all, err := p.List(ctx)
	if err != nil || len(all) != 2*n {
		t.Fatalf("users = %d (%v), want %d", len(all), err, 2*n)
	}
	events, err := importOutbox(t, dsn).Pending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != n {
		t.Errorf("events = %d, want %d (only the imported users)", len(events), n)
	}
	for _, e := range events {
		if e.AggregateID == "" || e.TenantID != importTenantID {
			t.Errorf("event wrong after concurrent writes: %+v", e)
		}
	}
}

// rejectingClient is a relay recipient that rejects the new event type
// (HTTP 422 — the classification the relay dead-letters, exactly what a
// recipient that does not yet support snaplink.audit.user.import returns).
type rejectingClient struct{}

func (rejectingClient) Publish(context.Context, *commerce.OutboxEvent) (auditgovernance.Receipt, error) {
	return auditgovernance.Receipt{}, &auditgovernance.HTTPStatusError{StatusCode: http.StatusUnprocessableEntity}
}

// Failure mode: recipient rejection. A relay whose recipient rejects the
// new event type dead-letters the row (no silent loss — the event stays
// durable), and the operator's ReplayOutbox + a supporting recipient
// redeliver it. This is the quarantine/replay safety net the design
// documents.
func TestImportGovernance_RecipientRejectionDeadLetterAndReplay(t *testing.T) {
	ctx := context.Background()
	p, dsn := newImportDB(t)
	u := &sso.User{ID: "csv:u@x.z", Provider: "csv", Email: "u@x.z"}
	if err := p.ImportUser(ctx, u, importEvent(importTenantID, u)); err != nil {
		t.Fatal(err)
	}
	outbox := importOutbox(t, dsn)

	rejecting, err := auditgovernance.NewRelay(outbox, rejectingClient{}, auditgovernance.RelayConfig{
		Owner: "e2e-rejecting-recipient",
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := rejecting.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce with rejecting recipient: %v", err)
	}
	if res.Dead != 1 {
		t.Fatalf("dead-lettered = %d, want 1 (rejection must not be silent)", res.Dead)
	}

	// No silent loss: the event is durable in a terminal state.
	dead, err := outbox.ListDeadOutbox(ctx, 10)
	if err != nil || len(dead) != 1 || dead[0].ID != "import:"+importTenantID+":"+u.ID {
		t.Fatalf("dead-letter rows = %+v (%v), want the import event", dead, err)
	}

	// Safety net: replay, then a supporting recipient delivers it.
	if err := outbox.ReplayOutbox(ctx, dead[0].ID, time.Now().UTC()); err != nil {
		t.Fatalf("ReplayOutbox: %v", err)
	}
	capture := &captureClient{}
	accepting, err := auditgovernance.NewRelay(outbox, capture, auditgovernance.RelayConfig{
		Owner: "e2e-accepting-recipient",
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err = accepting.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce after replay: %v", err)
	}
	if res.Delivered != 1 || capture.count() != 1 {
		t.Errorf("after replay delivered=%d capture=%d, want 1/1", res.Delivered, capture.count())
	}
	if pending, _ := outbox.Pending(ctx); len(pending) != 0 {
		t.Errorf("pending after replay delivery = %d, want 0", len(pending))
	}
}
