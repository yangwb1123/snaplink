package importcmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/infrastructure/auditoutbox"
	sso "github.com/yangwb1123/snaplink/interfaces/sso"
)

// ---- parser tests ----

// TestParseAuth0 covers the Auth0 export shape: a JSON array of user
// objects with bcrypt password_hash. Empty rows (no email/user_id) are
// skipped; the hash format is auto-detected.
func TestParseAuth0(t *testing.T) {
	in := `[
		{"user_id":"auth0|abc","email":"a@example.com","name":"Alice","password_hash":"$2b$10$abcdefghijklmnopqrstuv"},
		{"user_id":"","email":"","name":"empty"},
		{"user_id":"auth0|def","email":"b@example.com","name":"Bob"}
	]`
	users, err := parseInput("auth0", strings.NewReader(in))
	if err != nil {
		t.Fatalf("parseAuth0: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("got %d users; want 2 (empty row skipped)", len(users))
	}
	if users[0].HashFormat != "bcrypt" {
		t.Errorf("user[0].HashFormat = %q; want bcrypt", users[0].HashFormat)
	}
	if users[0].Provider != "auth0" || users[0].Email != "a@example.com" {
		t.Errorf("user[0] = %+v; unexpected fields", users[0])
	}
	// Second user has no hash → empty format.
	if users[1].Hash != "" || users[1].HashFormat != "" {
		t.Errorf("user[1] should carry no hash; got %+v", users[1])
	}
}

func TestParseAuth0_BadJSON(t *testing.T) {
	if _, err := parseInput("auth0", strings.NewReader("not json")); err == nil {
		t.Fatal("expected decode error for malformed auth0 json")
	}
}

// TestParseKeycloak_RealmObject covers the full realm export shape
// ({"users":[...]}) including pbkdf2-sha256 hash reconstruction and the
// firstName+lastName name join.
func TestParseKeycloak_RealmObject(t *testing.T) {
	in := `{
		"realm":"demo",
		"users":[
			{"id":"kc-1","username":"alice","email":"a@kc.example","firstName":"Al","lastName":"Ice",
			 "credentials":[{"type":"password",
			   "secretData":"{\"value\":\"HASHVAL\",\"salt\":\"SALT\"}",
			   "credentialData":"{\"hashIterations\":27500,\"algorithm\":\"pbkdf2-sha256\"}"}]},
			{"id":"","username":"","email":""}
		]
	}`
	users, err := parseInput("keycloak", strings.NewReader(in))
	if err != nil {
		t.Fatalf("parseKeycloak: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("got %d users; want 1 (empty row skipped)", len(users))
	}
	u := users[0]
	if u.Name != "Al Ice" {
		t.Errorf("Name = %q; want 'Al Ice'", u.Name)
	}
	if u.HashFormat != "pbkdf2-sha256" {
		t.Errorf("HashFormat = %q; want pbkdf2-sha256", u.HashFormat)
	}
	if u.Hash != "pbkdf2_sha256$27500$SALT$HASHVAL" {
		t.Errorf("Hash = %q; want reconstructed django encoding", u.Hash)
	}
}

// TestParseKeycloak_BareArrayBranch exercises the bare-top-level-array
// branch of parseKeycloak — the shape a Keycloak PARTIAL export produces.
// The decoder consumes the leading '[' then decodes elements one-by-one,
// so a bare array imports correctly (it previously failed with a decode
// error because Decode was called expecting another '[').
func TestParseKeycloak_BareArrayBranch(t *testing.T) {
	in := `[
		{"id":"kc-2","username":"bob","email":"b@kc.example"},
		{"id":"kc-3","username":"carol","email":"c@kc.example"}
	]`
	users, err := parseInput("keycloak", strings.NewReader(in))
	if err != nil {
		t.Fatalf("parseKeycloak bare array: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("got %d users, want 2 (bare array import): %+v", len(users), users)
	}
	if users[0].Email != "b@kc.example" || users[1].Email != "c@kc.example" {
		t.Errorf("unexpected users: %+v", users)
	}
}

// TestParseKeycloak_HashVariants exercises the argon2id (PHC + opaque)
// and bcrypt branches of extractKeycloakHash, plus the unknown-algorithm
// fallback (no hash).
func TestParseKeycloak_HashVariants(t *testing.T) {
	cases := []struct {
		name       string
		alg        string
		value      string
		wantHash   string
		wantFormat string
	}{
		{"argon2id-phc", "argon2id", "$argon2id$v=19$m=7168,t=5,p=1$c2FsdA$aGFzaA", "$argon2id$v=19$m=7168,t=5,p=1$c2FsdA$aGFzaA", "argon2id"},
		{"argon2id-opaque", "argon2id", "rawbytes", "rawbytes", "argon2id"},
		{"bcrypt", "bcrypt", "$2b$10$abcdefghijklmnopqrstuv", "$2b$10$abcdefghijklmnopqrstuv", "bcrypt"},
		{"unknown-alg", "scrypt", "whatever", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Use the realm-object ({"users":[...]}) shape so the
			// working code path drives extractKeycloakHash.
			in := `{"users":[{"id":"u","username":"u","credentials":[{"type":"password",` +
				`"secretData":"{\"value\":\"` + tc.value + `\",\"salt\":\"s\"}",` +
				`"credentialData":"{\"hashIterations\":1,\"algorithm\":\"` + tc.alg + `\"}"}]}]}`
			users, err := parseInput("keycloak", strings.NewReader(in))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(users) != 1 {
				t.Fatalf("got %d users; want 1", len(users))
			}
			if users[0].Hash != tc.wantHash || users[0].HashFormat != tc.wantFormat {
				t.Errorf("hash=%q fmt=%q; want hash=%q fmt=%q",
					users[0].Hash, users[0].HashFormat, tc.wantHash, tc.wantFormat)
			}
		})
	}
}

// TestParseKeycloak_NonPasswordCredentialSkipped — a credential whose
// type isn't "password" (e.g. otp) must be ignored, leaving no hash.
func TestParseKeycloak_NonPasswordCredentialSkipped(t *testing.T) {
	in := `{"users":[{"id":"u","username":"u","credentials":[{"type":"otp","secretData":"{}","credentialData":"{}"}]}]}`
	users, err := parseInput("keycloak", strings.NewReader(in))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(users) != 1 || users[0].Hash != "" {
		t.Errorf("non-password credential should yield no hash; got %+v", users)
	}
}

// TestParseKeycloak_SkipsUnknownFieldsAndBadSecretData drives the
// unknown-field skip in decodeKeycloakObject (the leading "realm" /
// "id" keys before "users") and the malformed-SecretData skip in
// extractKeycloakHash (invalid JSON in secretData → credential
// ignored, leaving no hash).
func TestParseKeycloak_SkipsUnknownFieldsAndBadSecretData(t *testing.T) {
	in := `{
		"id":"realm-uuid",
		"realm":"demo",
		"enabled":true,
		"users":[
			{"id":"kc-9","username":"u9","credentials":[{"type":"password",
			   "secretData":"not-json","credentialData":"{}"}]}
		]
	}`
	users, err := parseInput("keycloak", strings.NewReader(in))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("got %d users; want 1", len(users))
	}
	if users[0].Hash != "" {
		t.Errorf("malformed secretData should yield no hash; got %q", users[0].Hash)
	}
}

// TestParseKeycloak_BadCredentialData covers the CredentialData
// unmarshal-failure skip in extractKeycloakHash.
func TestParseKeycloak_BadCredentialData(t *testing.T) {
	in := `{"users":[{"id":"u","username":"u","credentials":[{"type":"password",` +
		`"secretData":"{\"value\":\"v\",\"salt\":\"s\"}","credentialData":"not-json"}]}]}`
	users, err := parseInput("keycloak", strings.NewReader(in))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(users) != 1 || users[0].Hash != "" {
		t.Errorf("malformed credentialData should yield no hash; got %+v", users)
	}
}

func TestParseKeycloak_BadJSON(t *testing.T) {
	if _, err := parseInput("keycloak", strings.NewReader("garbage")); err == nil {
		t.Fatal("expected error for malformed keycloak json")
	}
}

// TestParseKeycloak_UnexpectedToken — a top-level scalar (not [ or {)
// is rejected.
func TestParseKeycloak_UnexpectedToken(t *testing.T) {
	if _, err := parseInput("keycloak", strings.NewReader(`"a string"`)); err == nil {
		t.Fatal("expected error for non-array/object top-level token")
	}
}

// TestParseCSV covers header mapping (case-insensitive), explicit and
// auto-detected hash formats, the username-only row, and skipping of
// rows with neither username nor email.
func TestParseCSV(t *testing.T) {
	in := "Username,Email,Name,Password_Hash,Hash_Format\n" +
		"alice,a@example.com,Alice,$2a$10$xxxxxxxxxxxxxxxxxxxxxx,\n" + // auto-detect bcrypt
		"bob,b@example.com,Bob,deadbeef,pbkdf2-sha256\n" + // explicit format
		",,,,\n" + // skipped (no username/email)
		"carol,,Carol,,\n" // username only, no hash
	users, err := parseInput("csv", strings.NewReader(in))
	if err != nil {
		t.Fatalf("parseCSV: %v", err)
	}
	if len(users) != 3 {
		t.Fatalf("got %d users; want 3 (blank row skipped)", len(users))
	}
	if users[0].HashFormat != "bcrypt" {
		t.Errorf("alice format = %q; want auto-detected bcrypt", users[0].HashFormat)
	}
	if users[1].HashFormat != "pbkdf2-sha256" {
		t.Errorf("bob format = %q; want explicit pbkdf2-sha256", users[1].HashFormat)
	}
	if users[2].ExternalID != "carol" || users[2].Hash != "" {
		t.Errorf("carol = %+v; want username-only no-hash", users[2])
	}
}

func TestParseCSV_BadHeader(t *testing.T) {
	// An unterminated quote in the header makes the first Read fail.
	if _, err := parseInput("csv", strings.NewReader("\"unterminated")); err == nil {
		t.Fatal("expected error reading malformed csv header")
	}
}

func TestParseCSV_BadRow(t *testing.T) {
	// Wrong field count on a data row surfaces as a per-line error.
	in := "email,name\na@example.com,Alice,extra\n"
	if _, err := parseInput("csv", strings.NewReader(in)); err == nil {
		t.Fatal("expected error for csv row with wrong field count")
	}
}

func TestParseInput_UnknownFormat(t *testing.T) {
	if _, err := parseInput("ldif", strings.NewReader("")); err == nil {
		t.Fatal("expected error for unknown format")
	}
}

// ---- hash detection ----

func TestDetectHashFormat(t *testing.T) {
	cases := map[string]string{
		"$2a$10$abc":          "bcrypt",
		"$2b$10$abc":          "bcrypt",
		"$2y$10$abc":          "bcrypt",
		"$argon2id$v=19$m=1":  "argon2id",
		"pbkdf2_sha256$1$s$h": "pbkdf2-sha256",
		"pbkdf2_sha512$1$s$h": "pbkdf2-sha512",
		"plaintextnonsense":   "",
		"":                    "",
	}
	for in, want := range cases {
		if got := detectHashFormat(in); got != want {
			t.Errorf("detectHashFormat(%q) = %q; want %q", in, got, want)
		}
	}
}

// ---- ID derivation ----

func TestDeriveID(t *testing.T) {
	if got := deriveID("auth0|abc", "x@y.z", "auth0"); got != "auth0:auth0_abc" {
		t.Errorf("source-id derive = %q; want sanitized provider:source", got)
	}
	if got := deriveID("", "x@y.z", "csv"); got != "csv:x@y.z" {
		t.Errorf("email derive = %q; want csv:x@y.z", got)
	}
	// No source ID and no email → time-based fallback with provider prefix.
	got := deriveID("", "", "keycloak")
	if !strings.HasPrefix(got, "keycloak:") {
		t.Errorf("fallback derive = %q; want keycloak: prefix", got)
	}
}

func TestSanitizeID(t *testing.T) {
	got := sanitizeID("auth0|a\x00b\nc\rd")
	if strings.ContainsAny(got, "|\x00\n\r") {
		t.Errorf("sanitizeID left problematic chars: %q", got)
	}
	if got != "auth0_a_b_c_d" {
		t.Errorf("sanitizeID = %q; want underscores for control/pipe chars", got)
	}
}

// ---- openInput ----

func TestOpenInput_File(t *testing.T) {
	path := filepath.Join(t.TempDir(), "in.json")
	if err := os.WriteFile(path, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	rc, err := openInput(path)
	if err != nil {
		t.Fatalf("openInput: %v", err)
	}
	defer func() { _ = rc.Close() }()
	b, _ := io.ReadAll(rc)
	if string(b) != "[]" {
		t.Errorf("read %q; want []", b)
	}
}

func TestOpenInput_Stdin(t *testing.T) {
	rc, err := openInput("-")
	if err != nil {
		t.Fatalf("openInput(-): %v", err)
	}
	// Closing the NopCloser around os.Stdin must not close the real stdin.
	if err := rc.Close(); err != nil {
		t.Errorf("close stdin nopcloser: %v", err)
	}
}

func TestOpenInput_Missing(t *testing.T) {
	if _, err := openInput(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected error opening a missing file")
	}
}

// ---- DB write path ----

func newTestProvider(t *testing.T) userStore {
	t.Helper()
	p, _ := newTestProviderDSN(t)
	return p
}

// newTestProviderDSN is newTestProvider plus the DSN, so tests can open a
// second handle (the outbox store) on the same sqlite file.
func newTestProviderDSN(t *testing.T) (userStore, string) {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "users.db")
	p, err := openDB("sqlite", dsn, "")
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p, dsn
}

// readOutboxEvents opens a second handle on the same sqlite file and
// returns the pending/leased governance events the import wrote.
func readOutboxEvents(t *testing.T, dsn string) []*commerce.OutboxEvent {
	t.Helper()
	store, err := auditoutbox.NewSQLiteOutboxStore(dsn)
	if err != nil {
		t.Fatalf("outbox store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	events, err := store.Pending(context.Background())
	if err != nil {
		t.Fatalf("pending events: %v", err)
	}
	return events
}

func TestOpenDB_BadDSN(t *testing.T) {
	if _, err := openDB("sqlite", "file:/nonexistent-dir-zzz/users.db?mode=ro", ""); err == nil {
		t.Fatal("expected error opening DB in a missing directory")
	}
}

// TestToSSOUser confirms hash + format land in Attributes and that a
// user with no hash gets an empty attribute map (no stray keys).
func TestToSSOUser(t *testing.T) {
	withHash := toSSOUser(importedUser{
		ID: "id-1", ExternalID: "ext", Provider: "auth0",
		Email: "a@b.c", Name: "A", Hash: "$2b$h", HashFormat: "bcrypt",
	})
	if withHash.Attributes["password_hash"] != "$2b$h" ||
		withHash.Attributes["password_hash_format"] != "bcrypt" {
		t.Errorf("hash attrs missing: %+v", withHash.Attributes)
	}
	noHash := toSSOUser(importedUser{ID: "id-2", Email: "x@y.z"})
	if len(noHash.Attributes) != 0 {
		t.Errorf("no-hash user should have empty attrs; got %+v", noHash.Attributes)
	}
}

// TestRunImport_PersistsAndUpserts drives the full write path against a
// real SQLite DB, then re-reads to confirm the rows + hash attributes
// persisted, and that a second import upserts rather than erroring.
func TestRunImport_PersistsAndUpserts(t *testing.T) {
	p := newTestProvider(t)
	users := []importedUser{
		{ID: "auth0:1", ExternalID: "1", Provider: "auth0", Email: "a@x.z", Name: "A", Hash: "$2b$h", HashFormat: "bcrypt"},
		{ID: "auth0:2", ExternalID: "2", Provider: "auth0", Email: "b@x.z", Name: "B"},
	}
	out := captureStdout(t, func() {
		if err := runImport(context.Background(), p, "tenant-acme", users, 1); err != nil {
			t.Fatalf("runImport: %v", err)
		}
	})
	if !strings.Contains(out, "imported 2 users") {
		t.Errorf("output = %q; want 'imported 2 users'", out)
	}

	got, err := p.GetByID(context.Background(), "auth0:1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Email != "a@x.z" || got.Attributes["password_hash"] != "$2b$h" {
		t.Errorf("persisted user = %+v; missing email/hash", got)
	}

	// Re-import with a changed name → upsert, no duplicate, no error.
	users[0].Name = "A2"
	if err := runImport(context.Background(), p, "tenant-acme", users, 100); err != nil {
		t.Fatalf("re-import: %v", err)
	}
	got2, _ := p.GetByID(context.Background(), "auth0:1")
	if got2.Name != "A2" {
		t.Errorf("upsert did not update name; got %q", got2.Name)
	}
	all, _ := p.List(context.Background())
	if len(all) != 2 {
		t.Errorf("got %d rows after re-import; want 2 (upsert, not insert)", len(all))
	}
}

// TestRunImport_EmitsOneEventPerUser (AC5) — the CLI wiring proof: each
// imported user produces exactly one governance event in the SAME file's
// audit_outbox, tenant-tied to the --tenant value, and a re-import of the
// same file produces ZERO new events (deterministic idempotency keys)
// while user rows still upsert.
func TestRunImport_EmitsOneEventPerUser(t *testing.T) {
	p, dsn := newTestProviderDSN(t)
	ctx := context.Background()
	users := []importedUser{
		{ID: "auth0:1", ExternalID: "1", Provider: "auth0", Email: "a@x.z", Name: "A", Hash: "$2b$h", HashFormat: "bcrypt"},
		{ID: "auth0:2", ExternalID: "2", Provider: "auth0", Email: "b@x.z", Name: "B"},
	}
	if err := runImport(ctx, p, "tenant-acme", users, 1); err != nil {
		t.Fatalf("runImport: %v", err)
	}

	events := readOutboxEvents(t, dsn)
	if len(events) != 2 {
		t.Fatalf("events after import = %d, want 2 (one per user)", len(events))
	}
	ids := map[string]bool{}
	for _, e := range events {
		ids[e.AggregateID] = true
		if e.TenantID != "tenant-acme" {
			t.Errorf("event tenant = %q, want the --tenant value", e.TenantID)
		}
		if e.Type != importEventType {
			t.Errorf("event type = %q, want %q", e.Type, importEventType)
		}
		if e.Payload["user_id"] != e.AggregateID || e.Payload["email"] != "" {
			t.Errorf("event payload not bounded/redacted: %+v", e.Payload)
		}
	}
	if !ids["auth0:1"] || !ids["auth0:2"] {
		t.Errorf("event aggregate IDs = %v; want the imported set", ids)
	}

	// Re-import the same file (changed name only) → zero new events.
	users[0].Name = "A2"
	if err := runImport(ctx, p, "tenant-acme", users, 100); err != nil {
		t.Fatalf("re-import: %v", err)
	}
	events = readOutboxEvents(t, dsn)
	if len(events) != 2 {
		t.Errorf("events after re-import = %d, want still 2 (idempotent insert)", len(events))
	}
	got, _ := p.GetByID(ctx, "auth0:1")
	if got.Name != "A2" {
		t.Errorf("re-import upsert did not apply; name = %q", got.Name)
	}
}

// TestNewImportFact pins the CLI's event policy: deterministic ID/key,
// bounded redacted payload (never hash/email/attributes), canonical
// digest, and full Validate() conformance.
func TestNewImportFact(t *testing.T) {
	u := &sso.User{ID: "csv:a@x.z", Provider: "csv", Email: "a@x.z"}
	fact := newImportFact("tenant-acme", u)
	wantKey := "import:tenant-acme:csv:a@x.z"
	if fact.ID != wantKey || fact.IdempotencyKey != wantKey {
		t.Errorf("ID/key = %q/%q, want deterministic %q", fact.ID, fact.IdempotencyKey, wantKey)
	}
	if fact.Type != importEventType || fact.TenantID != "tenant-acme" {
		t.Errorf("type/tenant = %q/%q", fact.Type, fact.TenantID)
	}
	if fact.AggregateType != "user" || fact.AggregateID != u.ID || fact.AggregateVersion != 1 {
		t.Errorf("aggregate = %+v", fact)
	}
	if fact.Status != commerce.OutboxPending {
		t.Errorf("status = %q, want pending", fact.Status)
	}
	if err := fact.Validate(); err != nil {
		t.Fatalf("newImportFact must satisfy OutboxEvent.Validate: %v", err)
	}
	// Bounded, redacted projection: user_id + provider only.
	if len(fact.Payload) != 2 || fact.Payload["user_id"] != u.ID || fact.Payload["provider"] != "csv" {
		t.Errorf("payload = %+v; want user_id+provider only", fact.Payload)
	}
	for _, key := range []string{"email", "password_hash", "password_hash_format"} {
		if _, present := fact.Payload[key]; present {
			t.Errorf("payload leaks %q: %+v", key, fact.Payload)
		}
	}
	if fact.PayloadDigest != digestPayload(fact.Payload) {
		t.Errorf("digest %q != canonical digest", fact.PayloadDigest)
	}
	// Determinism: same tenant+user → same ID and digest; new tenant → new ID.
	again := newImportFact("tenant-acme", u)
	if again.ID != fact.ID || again.PayloadDigest != fact.PayloadDigest {
		t.Error("same tenant+user must produce the identical event identity")
	}
	other := newImportFact("tenant-other", u)
	if other.ID == fact.ID {
		t.Error("different tenant must produce a different event ID")
	}
}

// TestDigestPayload pins the canonical digest: map key order must not
// change the digest (fact-equality across backends depends on it).
func TestDigestPayload(t *testing.T) {
	a := digestPayload(map[string]string{"user_id": "u1", "provider": "csv"})
	b := digestPayload(map[string]string{"provider": "csv", "user_id": "u1"})
	if a == "" || a != b {
		t.Errorf("digest not canonical across key order: %q vs %q", a, b)
	}
}

// TestRunImport_SkipsBadRows — a user with an empty ID fails the write
// and is reported as skipped without aborting the whole run. (AC2 CLI
// leg: the failing row rolls back its own pair; accounting unchanged.)
func TestRunImport_SkipsBadRows(t *testing.T) {
	p := newTestProvider(t)
	users := []importedUser{
		{ID: "", Email: "bad@x.z"},    // empty ID → ImportUser errors
		{ID: "ok:1", Email: "ok@x.z"}, // good
	}
	out := captureStdout(t, func() {
		if err := runImport(context.Background(), p, "tenant-acme", users, 100); err != nil {
			t.Fatalf("runImport should not return a fatal error: %v", err)
		}
	})
	if !strings.Contains(out, "imported 1 users") || !strings.Contains(out, "skipped 1") {
		t.Errorf("output = %q; want imported 1 / skipped 1", out)
	}
}

// TestRunImport_DefaultBatchSize — a non-positive batch size falls back
// to the default rather than dividing by zero / looping forever.
func TestRunImport_DefaultBatchSize(t *testing.T) {
	p := newTestProvider(t)
	users := []importedUser{{ID: "x:1", Email: "x@x.z"}}
	if err := runImport(context.Background(), p, "tenant-acme", users, 0); err != nil {
		t.Fatalf("runImport with batch=0: %v", err)
	}
	if all, _ := p.List(context.Background()); len(all) != 1 {
		t.Errorf("got %d rows; want 1", len(all))
	}
}

// ---- dry run ----

// TestRunDryRun_TruncatesPreview — with more than the preview cap, the
// summary prints the count, the first N, and an "and M more" line.
func TestRunDryRun_TruncatesPreview(t *testing.T) {
	var users []importedUser
	for i := 0; i < 8; i++ {
		users = append(users, importedUser{
			ID: "id-" + string(rune('a'+i)), Email: "u@x.z", HashFormat: "bcrypt",
		})
	}
	out := captureStdout(t, func() { runDryRun(users) })
	if !strings.Contains(out, "would import 8 users") {
		t.Errorf("missing total count: %q", out)
	}
	if !strings.Contains(out, "and 3 more") {
		t.Errorf("missing truncation line: %q", out)
	}
	if !strings.Contains(out, "[bcrypt]") {
		t.Errorf("missing hash summary: %q", out)
	}
}

// TestRunDryRun_NoHash — a user with no hash shows the "(no hash)"
// marker and no truncation line when under the preview cap.
func TestRunDryRun_NoHash(t *testing.T) {
	out := captureStdout(t, func() {
		runDryRun([]importedUser{{ID: "id-1", Email: "a@x.z"}})
	})
	if !strings.Contains(out, "(no hash)") {
		t.Errorf("missing (no hash) marker: %q", out)
	}
	if strings.Contains(out, "more") {
		t.Errorf("unexpected truncation line: %q", out)
	}
}

// TestRun_DryRun drives Run through the dry-run branch (parse flags →
// openInput(file) → parseInput → runDryRun → return 0), which never
// touches a DB and never calls os.Exit. args carry NO --tenant (AC5:
// --dry-run without --tenant succeeds — R4 exemption).
func TestRun_DryRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.csv")
	if err := os.WriteFile(path, []byte("email,name\na@x.z,Alice\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var code int
	out := captureStdout(t, func() {
		code = Run([]string{"--format", "csv", "--file", path, "--dry-run"})
	})
	if code != 0 {
		t.Errorf("Run exit code = %d; want 0", code)
	}
	if !strings.Contains(out, "dry-run") || !strings.Contains(out, "would import 1 users") {
		t.Errorf("dry-run Run output unexpected:\n%s", out)
	}
}

// TestRun_DryRunWithoutTenantTouchesNothing — dry-run with a --dsn
// pointing at a path that must never be created: zero events, zero user
// rows, zero DB file (AC5).
func TestRun_DryRunWithoutTenantTouchesNothing(t *testing.T) {
	csvPath := filepath.Join(t.TempDir(), "users.csv")
	if err := os.WriteFile(csvPath, []byte("email,name\nm@x.z,Mallory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "never-created.db")
	var code int
	captureStdout(t, func() {
		code = Run([]string{"--format", "csv", "--file", csvPath, "--dsn", "file:" + dbPath, "--dry-run"})
	})
	if code != 0 {
		t.Errorf("Run exit code = %d; want 0", code)
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Errorf("dry-run created the DB file; want no writes at all")
	}
}

// TestValidateTenantID pins the --tenant bounds: empty, over-long, and
// control-character values are rejected; a plain value passes.
func TestValidateTenantID(t *testing.T) {
	if err := validateTenantID(""); err == nil {
		t.Error("empty tenant must be rejected")
	}
	if err := validateTenantID(strings.Repeat("a", maxTenantLen+1)); err == nil {
		t.Error("over-long tenant must be rejected")
	}
	if err := validateTenantID("acme\ncorp"); err == nil {
		t.Error("control-character tenant must be rejected")
	}
	if err := validateTenantID("tenant-acme"); err != nil {
		t.Errorf("plain tenant rejected: %v", err)
	}
}

// TestParseFlags_MissingTenant_Exit2 runs parseFlags in a child process
// (it terminates via os.Exit(2), so it cannot run in-process) and asserts
// the exit code — the AC5 --tenant gate.
func TestParseFlags_MissingTenant_Exit2(t *testing.T) {
	if os.Getenv("IMPORTCMD_HELPER") == "1" {
		parseFlags([]string{"--format", "csv", "--dsn", "file:x.db"})
		os.Exit(0) // unreachable: parseFlags must exit 2
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestParseFlags_MissingTenant_Exit2")
	cmd.Env = append(os.Environ(), "IMPORTCMD_HELPER=1")
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("child process: %v; want exit 2", err)
	}
	if exitErr.ExitCode() != 2 {
		t.Fatalf("exit code = %d, want 2 (--tenant required for writes)", exitErr.ExitCode())
	}
}

// TestRun_FullImport drives Run through the write path (parse → openInput
// → parseInput → openDB → runImport → return 0) against a real SQLite DB,
// then confirms the row landed AND the governance event exists in the same
// file's audit_outbox.
func TestRun_FullImport(t *testing.T) {
	csvPath := filepath.Join(t.TempDir(), "users.csv")
	if err := os.WriteFile(csvPath, []byte("email,name,password_hash\nm@x.z,Mallory,$2b$10$abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "import.db")
	dsn := "file:" + dbPath
	var code int
	out := captureStdout(t, func() {
		code = Run([]string{"--format", "csv", "--file", csvPath, "--dsn", dsn, "--tenant", "tenant-acme"})
	})
	if code != 0 {
		t.Errorf("Run exit code = %d; want 0", code)
	}
	if !strings.Contains(out, "imported 1 users") {
		t.Errorf("full-import Run output unexpected:\n%s", out)
	}

	// Re-open the DB and confirm persistence.
	p, err := openDB("sqlite", dsn, "")
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer func() { _ = p.Close() }()
	u, err := p.GetByID(context.Background(), "csv:m@x.z")
	if err != nil {
		t.Fatalf("GetByID after Run import: %v", err)
	}
	if u.Email != "m@x.z" || u.Attributes["password_hash_format"] != "bcrypt" {
		t.Errorf("imported user wrong: %+v", u)
	}
	events := readOutboxEvents(t, dsn)
	if len(events) != 1 || events[0].TenantID != "tenant-acme" || events[0].AggregateID != "csv:m@x.z" {
		t.Errorf("governance event missing/wrong after Run import: %+v", events)
	}
}

// captureStdout redirects os.Stdout for the duration of fn and returns
// what was written, trimmed. Mirrors the helper used by the other CLI
// tests in this repo.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()
	defer func() { os.Stdout = orig }()
	fn()
	_ = w.Close()
	out := <-done
	os.Stdout = orig
	return string(bytes.TrimSpace(out))
}

func TestOpenDB_UnknownBackend(t *testing.T) {
	t.Parallel()
	if _, err := openDB("mysql", "dsn", ""); err == nil {
		t.Fatal("expected error for unsupported --backend")
	}
}

// postgres.Open rejects an empty DSN before dialing (infrastructure/postgres/pool.go),
// so this exercises the postgres branch without a live database.
func TestOpenDB_PostgresEmptyDSN(t *testing.T) {
	t.Parallel()
	if _, err := openDB("postgres", "", ""); err == nil {
		t.Fatal("expected error for postgres backend with empty DSN")
	}
}

// testPostgresDSN returns the integration DSN or skips — CI without a DB skips.
func testPostgresDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("SSO_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SSO_TEST_POSTGRES_DSN not set — skipping postgres integration test")
	}
	return dsn
}

// TestRunImport_Postgres_PersistsAndUpserts drives the full write path against
// a real Postgres users table via the same userStore seam the CLI uses, then
// re-reads through core.UserProvider to confirm the hash attributes landed.
// Unique IDs + Delete cleanup (not TRUNCATE) — the infrastructure/postgres
// package tests TRUNCATE this table and may run concurrently on the same DSN.
// The governance outbox rows this run enqueues are deleted in cleanup for the
// same reason: tenantcommerce tests claim rows from tenant_commerce_outbox.
func TestRunImport_Postgres_PersistsAndUpserts(t *testing.T) {
	t.Parallel()
	p, err := openDB("postgres", testPostgresDSN(t), os.Getenv("SSO_TEST_POSTGRES_DIALECT"))
	if err != nil {
		t.Fatalf("openDB postgres: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	ctx := context.Background()
	id := "importtest:" + strings.ToLower(t.Name())
	t.Cleanup(func() { _ = p.Delete(ctx, id) })

	users := []importedUser{{
		ID: id, ExternalID: "pg-1", Provider: "auth0",
		Email: "pg@x.z", Name: "PG", Hash: "$2b$h", HashFormat: "bcrypt",
	}}
	if err := runImport(ctx, p, "tenant-pg", users, 100); err != nil {
		t.Fatalf("runImport: %v", err)
	}
	got, err := p.GetByID(ctx, id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	// Seam contract with domains/authenticators.StoredHashVerifier.
	if got.Attributes["password_hash"] != "$2b$h" || got.Attributes["password_hash_format"] != "bcrypt" {
		t.Errorf("hash attrs did not round-trip: %+v", got.Attributes)
	}
	users[0].Name = "PG2"
	if err := runImport(ctx, p, "tenant-pg", users, 100); err != nil {
		t.Fatalf("re-import: %v", err)
	}
	got2, _ := p.GetByID(ctx, id)
	if got2.Name != "PG2" {
		t.Errorf("upsert did not update name; got %q", got2.Name)
	}
	// Clean the governance rows this run enqueued (tenantcommerce tests
	// claim tenant_commerce_outbox rows on a shared DSN).
	if s, ok := p.(postgresUserStore); ok {
		t.Cleanup(func() {
			_, _ = s.DB().ExecContext(ctx, `DELETE FROM tenant_commerce_outbox WHERE tenant_id='tenant-pg'`)
		})
	}
}
