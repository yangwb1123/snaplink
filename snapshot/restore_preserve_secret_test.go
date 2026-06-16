package snapshot_test

import (
	"context"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/snapshot"
)

// TestRestore_Overwrite_PreservesLiveClientSecret proves an Overwrite
// restore does NOT destroy a live client's credentials when the snapshot
// omits them. Client.Secret + RegistrationAccessToken are json:"-", so a
// serialized snapshot never carries them; previously restoreClients fed
// the empty incoming values straight into ClientStore.Update, which
// wholesale-replaced and wiped the live hashed secret (the client could
// no longer authenticate client_credentials/refresh on /token).
func TestRestore_Overwrite_PreservesLiveClientSecret(t *testing.T) {
	ctx := context.Background()

	// Live destination: a confidential client with a real secret + RAT.
	dst := defaultimpl.NewMemoryClientStore()
	if err := dst.Add(ctx, &sso.Client{
		ID:                      "web",
		Name:                    "Original",
		Secret:                  "live-secret",
		RegistrationAccessToken: "live-rat",
		Active:                  true,
	}); err != nil {
		t.Fatalf("seed live client: %v", err)
	}
	// Pre-condition: the secret authenticates.
	if err := dst.ValidateSecret(ctx, "web", "live-secret"); err != nil {
		t.Fatalf("pre-restore ValidateSecret: %v", err)
	}

	// Build a snapshot the way a real export does — round-trip through the
	// JSON codec so Secret/RegistrationAccessToken are dropped by json:"-",
	// exactly as a restored-from-disk snapshot would arrive.
	codec := snapshot.NewJSONCodec()
	raw, err := codec.Marshal(&snapshot.Snapshot{
		SchemaVersion:   snapshot.SchemaVersion,
		SnapshotID:      "snap-1",
		SourceNamespace: "sso-server",
		Resources: snapshot.Resources{
			Clients: []*sso.Client{{
				ID:     "web",
				Name:   "Updated Name",
				Active: true,
				// No Secret/RAT — json:"-" would have dropped them anyway.
			}},
		},
	})
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	snap, err := codec.Unmarshal(raw)
	if err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	// Sanity: the deserialized client truly carries no secret.
	if got := snap.Resources.Clients[0].Secret; got != "" {
		t.Fatalf("snapshot unexpectedly carries a secret: %q", got)
	}

	r := &snapshot.Restorer{Clients: dst}
	rep, err := r.Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeOverwrite})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := rep.Items[snapshot.CategoryClients].Updated; got != 1 {
		t.Errorf("clients updated=%d want 1", got)
	}

	// The non-secret field DID update.
	out, err := dst.Get(ctx, "web")
	if err != nil {
		t.Fatalf("Get after restore: %v", err)
	}
	if out.Name != "Updated Name" {
		t.Errorf("Name not updated: %q", out.Name)
	}

	// The live secret + RAT MUST survive the restore.
	if err := dst.ValidateSecret(ctx, "web", "live-secret"); err != nil {
		t.Errorf("post-restore ValidateSecret: live secret was destroyed: %v", err)
	}
	if out.RegistrationAccessToken == "" {
		t.Error("post-restore RegistrationAccessToken was wiped to empty")
	}
}
