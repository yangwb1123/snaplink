package snapshot_test

import (
	"context"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/snapshot"
	encryptionnone "github.com/yangwb1123/snaplink/interfaces/snapshot/encryptionnone"
	storageinline "github.com/yangwb1123/snaplink/interfaces/snapshot/storageinline"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// redactSourceStore builds a MemoryClientStore (which returns LIVE
// pointers from List — the exact backend that makes the no-live-mutation
// guarantee non-trivial) seeded with two clients carrying secrets + a
// registration access token.
func redactSourceStore(t *testing.T) *defaultimpl.MemoryClientStore {
	t.Helper()
	ctx := context.Background()
	cs := defaultimpl.NewMemoryClientStore()
	if err := cs.Add(ctx, &sso.Client{
		ID: "alpha", Name: "Alpha", Active: true,
		Secret:                  "alpha-secret",
		RegistrationAccessToken: "alpha-regtok",
		RedirectURIs:            []string{"https://a.example/cb"},
		AllowedScopes:           []string{"openid"},
	}); err != nil {
		t.Fatalf("add alpha: %v", err)
	}
	if err := cs.Add(ctx, &sso.Client{
		ID: "beta", Name: "Beta", Active: true,
		Secret:       "beta-secret",
		RedirectURIs: []string{"https://b.example/cb"},
	}); err != nil {
		t.Fatalf("add beta: %v", err)
	}
	return cs
}

func clientByID(clients []*sso.Client, id string) *sso.Client {
	for _, c := range clients {
		if c != nil && c.ID == id {
			return c
		}
	}
	return nil
}

// TestExportWithRedactionZerosSecrets proves the opt-in redactor empties
// the credential fields on the exported snapshot while leaving the
// non-secret material (id, name, redirect URIs, scopes) intact.
func TestExportWithRedactionZerosSecrets(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sn := &snapshot.Snapshotter{Clients: redactSourceStore(t)}

	snap, err := sn.Export(ctx, snapshot.ExportOptions{Redactor: snapshot.SnapshotRedactSecrets()})
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	alpha := clientByID(snap.Resources.Clients, "alpha")
	if alpha == nil {
		t.Fatal("alpha missing from snapshot")
	}
	if alpha.Secret != "" {
		t.Errorf("alpha.Secret = %q, want empty", alpha.Secret)
	}
	if alpha.RegistrationAccessToken != "" {
		t.Errorf("alpha.RegistrationAccessToken = %q, want empty", alpha.RegistrationAccessToken)
	}
	// Non-secret material must survive — that's the whole point of
	// inspection redaction.
	if alpha.Name != "Alpha" || len(alpha.RedirectURIs) != 1 || len(alpha.AllowedScopes) != 1 {
		t.Errorf("non-secret fields were disturbed: %+v", alpha)
	}
	if beta := clientByID(snap.Resources.Clients, "beta"); beta == nil || beta.Secret != "" {
		t.Errorf("beta secret not redacted: %+v", beta)
	}
}

// TestExportWithoutRedactionKeepsSecrets is the backward-compat gate:
// default ExportOptions (no redactor, no Snapshotter default) returns a
// snapshot whose clients still carry their secrets.  Secrets are stored as
// bcrypt hashes, so the snapshot carries the hash (not the plaintext).
func TestExportWithoutRedactionKeepsSecrets(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sn := &snapshot.Snapshotter{Clients: redactSourceStore(t)}

	snap, err := sn.Export(ctx, snapshot.ExportOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	alpha := clientByID(snap.Resources.Clients, "alpha")
	if alpha == nil {
		t.Fatal("alpha missing from snapshot")
	}
	// The stored Secret is a bcrypt hash — a non-redacted export must include
	// it (not empty it).  The hash starts with "$2".
	if alpha.Secret == "" {
		t.Error("default export zeroed alpha.Secret, want the stored bcrypt hash")
	}
	if !strings.HasPrefix(alpha.Secret, "$2") {
		t.Errorf("expected bcrypt hash in exported Secret, got %q", alpha.Secret)
	}
	if alpha.RegistrationAccessToken == "" {
		t.Error("default export zeroed alpha.RegistrationAccessToken, want the stored bcrypt hash")
	}
	if !strings.HasPrefix(alpha.RegistrationAccessToken, "$2") {
		t.Errorf("expected bcrypt hash in exported RegistrationAccessToken, got %q", alpha.RegistrationAccessToken)
	}
}

// TestRedactedExportDoesNotMutateLiveStore is the critical correctness
// test: after a redacted export, the SOURCE store's client objects must
// still hold their secrets. MemoryClientStore.List hands out live
// pointers, so without the export-local deep copy this would fail.
func TestRedactedExportDoesNotMutateLiveStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cs := redactSourceStore(t)
	sn := &snapshot.Snapshotter{Clients: cs}

	if _, err := sn.Export(ctx, snapshot.ExportOptions{Redactor: snapshot.SnapshotRedactSecrets()}); err != nil {
		t.Fatalf("export: %v", err)
	}

	// Read the live store back through its own API.
	live, err := cs.Get(ctx, "alpha")
	if err != nil {
		t.Fatalf("get alpha: %v", err)
	}
	// The live store holds a bcrypt hash of "alpha-secret" — it must not have
	// been zeroed by the redacted export.
	if live.Secret == "" {
		t.Errorf("LIVE store mutated: alpha.Secret was zeroed")
	}
	if !strings.HasPrefix(live.Secret, "$2") {
		t.Errorf("LIVE store mutated: alpha.Secret is not a bcrypt hash: %q", live.Secret)
	}
	if live.RegistrationAccessToken == "" {
		t.Errorf("LIVE store mutated: alpha.RegistrationAccessToken was zeroed")
	}
	// The credential grant must still validate after the redacted export.
	if err := cs.ValidateSecret(ctx, "alpha", "alpha-secret"); err != nil {
		t.Errorf("alpha can no longer authenticate after redacted export: %v", err)
	}
}

// TestDefaultExportRedactorApplies proves the Snapshotter-level default
// (the cmd wiring path for snapshot.redact_secrets) fires when no
// per-call redactor is supplied.
func TestDefaultExportRedactorApplies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sn := &snapshot.Snapshotter{
		Clients:               redactSourceStore(t),
		DefaultExportRedactor: snapshot.SnapshotRedactSecrets(),
	}
	snap, err := sn.Export(ctx, snapshot.ExportOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if alpha := clientByID(snap.Resources.Clients, "alpha"); alpha == nil || alpha.Secret != "" {
		t.Errorf("default redactor did not fire: %+v", alpha)
	}

	// Per-call override of nil... no: per-call non-nil wins; verify a
	// per-call redactor still works alongside a default (both redact).
	snap2, err := sn.Export(ctx, snapshot.ExportOptions{Redactor: snapshot.SnapshotRedactSecrets()})
	if err != nil {
		t.Fatalf("export 2: %v", err)
	}
	if alpha := clientByID(snap2.Resources.Clients, "alpha"); alpha == nil || alpha.Secret != "" {
		t.Errorf("per-call redactor did not fire: %+v", alpha)
	}
}

// TestComposeChainsRedactors proves Compose runs each redactor. The
// second redactor asserts the first already zeroed the secret, so a
// broken ordering would surface the secret.
func TestComposeChainsRedactors(t *testing.T) {
	t.Parallel()
	var sawZeroed bool
	probe := snapshot.RedactorFunc(func(s *snapshot.Snapshot) {
		if c := clientByID(s.Resources.Clients, "alpha"); c != nil {
			sawZeroed = c.Secret == ""
		}
	})
	r := snapshot.Compose(snapshot.SnapshotRedactSecrets(), probe)

	ctx := context.Background()
	sn := &snapshot.Snapshotter{Clients: redactSourceStore(t)}
	if _, err := sn.Export(ctx, snapshot.ExportOptions{Redactor: r}); err != nil {
		t.Fatalf("export: %v", err)
	}
	if !sawZeroed {
		t.Error("Compose did not run SnapshotRedactSecrets before the probe")
	}

	// Empty compose is a no-op redactor (does not panic, does not redact).
	noop := snapshot.Compose()
	sn2 := &snapshot.Snapshotter{Clients: redactSourceStore(t)}
	snap, err := sn2.Export(ctx, snapshot.ExportOptions{Redactor: noop})
	if err != nil {
		t.Fatalf("export noop: %v", err)
	}
	// Empty Compose is a no-op — the exported secret must be the stored bcrypt hash
	// (not empty and not the plaintext).
	alpha := clientByID(snap.Resources.Clients, "alpha")
	if alpha == nil || alpha.Secret == "" {
		t.Errorf("empty Compose must be a no-op (non-empty secret), got %+v", alpha)
	}
	if alpha != nil && !strings.HasPrefix(alpha.Secret, "$2") {
		t.Errorf("empty Compose must be a no-op (bcrypt hash expected), got Secret=%q", alpha.Secret)
	}
}

// TestRedactedSnapshotRoundTrips proves a redacted snapshot still
// serializes, seals, and loads through the pipeline — it just comes back
// with empty secrets (it is an inspection artifact, not a restore one).
func TestRedactedSnapshotRoundTrips(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sn := &snapshot.Snapshotter{Clients: redactSourceStore(t)}
	snap, err := sn.Export(ctx, snapshot.ExportOptions{Redactor: snapshot.SnapshotRedactSecrets()})
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	pipe := &snapshot.Pipeline{Sealer: encryptionnone.New()}
	store := storageinline.New()
	if err := pipe.Save(ctx, snap, store, snap.SnapshotID); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := pipe.Load(ctx, store, snap.SnapshotID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	alpha := clientByID(loaded.Resources.Clients, "alpha")
	if alpha == nil {
		t.Fatal("alpha missing after round-trip")
	}
	// Secret is json:"-" so it never serializes regardless; the load
	// must still produce a usable, secret-free client.
	if alpha.Secret != "" {
		t.Errorf("loaded alpha.Secret = %q, want empty", alpha.Secret)
	}
	if alpha.ID != "alpha" || alpha.Name != "Alpha" {
		t.Errorf("non-secret fields lost on round-trip: %+v", alpha)
	}
}

// TestSnapshotRedactSecretsNilSafe documents that the redactor tolerates
// nil snapshots / nil client entries without panicking.
func TestSnapshotRedactSecretsNilSafe(t *testing.T) {
	t.Parallel()
	r := snapshot.SnapshotRedactSecrets()
	r.Redact(nil)
	snap := &snapshot.Snapshot{Resources: snapshot.Resources{Clients: []*sso.Client{nil, {ID: "x", Secret: "s"}}}}
	r.Redact(snap)
	if snap.Resources.Clients[1].Secret != "" {
		t.Errorf("Secret not redacted in nil-mixed slice")
	}
}

// TestRedactedExportScrubsUserCredentials proves the redactor strips user
// credential attributes (password_hash + the bootstrap admin's PLAINTEXT
// seeded_password) from a shareable export while keeping profile attributes,
// AND -- the critical safety -- never mutates the LIVE user (which would strip
// password_hash and break login). MemoryUserProvider.List hands out live
// pointers, so the export-local copy is load-bearing.
func TestRedactedExportScrubsUserCredentials(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	if err := users.CreateOrUpdate(ctx, &sso.User{
		ID: "u1", Email: "u1@example.com", Name: "User One",
		Attributes: map[string]string{
			"password_hash":        "$2a$10$bcrypthashvalue",
			"password_hash_format": "bcrypt",
			"seeded_password":      "generated-plaintext-pw",
			"team":                 "platform",
		},
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	sn := &snapshot.Snapshotter{Users: users}

	snap, err := sn.Export(ctx, snapshot.ExportOptions{Redactor: snapshot.SnapshotRedactSecrets()})
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	var exported *sso.User
	for _, u := range snap.Resources.Users {
		if u != nil && u.ID == "u1" {
			exported = u
		}
	}
	if exported == nil {
		t.Fatal("u1 missing from snapshot")
	}
	for _, k := range []string{"password_hash", "password_hash_format", "seeded_password"} {
		if _, present := exported.Attributes[k]; present {
			t.Errorf("credential attr %q leaked in redacted snapshot", k)
		}
	}
	if exported.Attributes["team"] != "platform" {
		t.Errorf("non-secret profile attr dropped: %v", exported.Attributes)
	}

	// CRITICAL: the LIVE user must still hold its credentials.
	live, err := users.GetByID(ctx, "u1")
	if err != nil {
		t.Fatalf("get live u1: %v", err)
	}
	if live.Attributes["password_hash"] != "$2a$10$bcrypthashvalue" {
		t.Errorf("LIVE user mutated: password_hash = %q (login would break)", live.Attributes["password_hash"])
	}
	if live.Attributes["seeded_password"] != "generated-plaintext-pw" {
		t.Errorf("LIVE user mutated: seeded_password was stripped from the running store")
	}
}
