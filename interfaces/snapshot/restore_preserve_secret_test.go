package snapshot_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/snapshot"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// TestRestore_Overwrite_PreservesLiveClientSecret proves an Overwrite
// restore does NOT destroy a live client's credentials when the snapshot
// omits them. Client.Secret + RegistrationAccessToken are json:"-", so a
// serialized snapshot never carries them; previously restoreClients fed
// the empty incoming values straight into ClientStore.Update, which
// wholesale-replaced and wiped the live hashed secret (the client could
// no longer authenticate client_credentials/refresh on /token).
func TestRestore_Overwrite_PreservesLiveClientSecret(t *testing.T) {
	t.Parallel()
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

// mustCodecSnapshot round-trips a hand-built snapshot through the JSON
// codec exactly like a restored-from-disk artifact arrives: Secret and
// RegistrationAccessToken are dropped by json:"-".
func mustCodecSnapshot(t *testing.T, src *snapshot.Snapshot) *snapshot.Snapshot {
	t.Helper()
	raw, err := snapshot.NewJSONCodec().Marshal(src)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	snap, err := snapshot.NewJSONCodec().Unmarshal(raw)
	if err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	return snap
}

// mustClient is a confidential secret-auth client helper.
func mustClient(id string) *sso.Client {
	return &sso.Client{ID: id, Name: id, Active: true}
}

// TestRestore_FreshNodeMerge_RotatesSecretlessConfidentialClients proves
// Decision 1's fresh-node regeneration: a merge restore onto a node with no
// live records leaves every confidential client secret-less (the artifact
// never carries secrets), and the restorer rotates them via the SecretRotator
// capability, surfacing the new plaintext ONLY in the RPC response
// (Report.CredentialRecovery). Public clients (token_endpoint_auth_method
// "none") and federation-derived clients are never rotated (they hold no
// secret by design); a disabled confidential client is counted in
// RequiresRotation (flag-on-enable) but not rotated (the Active gate).
func TestRestore_FreshNodeMerge_RotatesSecretlessConfidentialClients(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	snap := mustCodecSnapshot(t, &snapshot.Snapshot{
		SchemaVersion:   snapshot.SchemaVersion,
		SnapshotID:      "snap-rotate",
		SourceNamespace: "sso-server",
		Resources: snapshot.Resources{
			Clients: []*sso.Client{
				mustClient("confidential-a"),
				mustClient("confidential-b"),
				{ID: "public-spa", Name: "SPA", Active: true, TokenEndpointAuthMethod: "none"},
				{ID: "disabled-conf", Name: "Off", Active: false},
				{ID: "fed-client", Name: "Federated", Active: true, Federation: true},
			},
		},
	})

	dst := defaultimpl.NewMemoryClientStore()
	rep, err := (&snapshot.Restorer{Clients: dst}).Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeMerge})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}

	// Exactly the two active confidential clients were rotated.
	if got := len(rep.CredentialRecovery); got != 2 {
		t.Fatalf("credential_recovery entries = %d, want 2 (%+v)", got, rep.CredentialRecovery)
	}
	rotated := map[string]string{}
	for _, c := range rep.CredentialRecovery {
		if c.Secret == "" {
			t.Errorf("recovery entry for %q carries no secret", c.ClientID)
		}
		rotated[c.ClientID] = c.Secret
	}
	if _, ok := rotated["public-spa"]; ok {
		t.Error("public client was rotated — it must never hold a secret")
	}
	if _, ok := rotated["fed-client"]; ok {
		t.Error("federation client was rotated — it authenticates via vouched JWKS")
	}
	if _, ok := rotated["disabled-conf"]; ok {
		t.Error("disabled client was rotated — the Active gate skips rotation")
	}

	// The disabled confidential client is flagged for rotation-on-enable.
	if got := rep.Items[snapshot.CategoryClients].RequiresRotation; got != 1 {
		t.Errorf("requires_rotation = %d, want 1 (disabled flag-on-enable)", got)
	}

	// The new plaintext secrets actually authenticate.
	for id, secret := range rotated {
		if err := dst.ValidateSecret(ctx, id, secret); err != nil {
			t.Errorf("ValidateSecret(%q, rotated secret): %v", id, err)
		}
	}
	// The public client must still reject a presented secret (none stored).
	if err := dst.ValidateSecret(ctx, "public-spa", ""); err == nil {
		t.Error("public client with empty stored secret authenticated — F1 regression")
	}
}

// TestRestore_RotationDryRun_PredictsWithoutMutation proves the dry-run
// prediction mirrors the real run exactly: RequiresRotation on dry-run equals
// the real run's rotated count PLUS its remaining RequiresRotation, with zero
// store mutations and zero CredentialRecovery entries.
func TestRestore_RotationDryRun_PredictsWithoutMutation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, mode := range []snapshot.RestoreMode{snapshot.ModeMerge, snapshot.ModeOverwrite} {
		t.Run(string(mode), func(t *testing.T) {
			// A fresh snapshot per subtest: MemoryClientStore stores the
			// passed client pointers and rotation mutates them in place, so
			// a real run would taint a shared snapshot for the next subtest.
			snap := mustCodecSnapshot(t, &snapshot.Snapshot{
				SchemaVersion:   snapshot.SchemaVersion,
				SnapshotID:      "snap-dry",
				SourceNamespace: "sso-server",
				Resources: snapshot.Resources{
					Clients: []*sso.Client{
						mustClient("confidential-a"),
						mustClient("confidential-b"),
						{ID: "disabled-conf", Name: "Off", Active: false},
						{ID: "public-spa", Name: "SPA", Active: true, TokenEndpointAuthMethod: "none"},
					},
				},
			})
			dryDst := defaultimpl.NewMemoryClientStore()
			dryRep, err := (&snapshot.Restorer{Clients: dryDst}).Restore(ctx, snap, snapshot.RestoreOptions{Mode: mode, DryRun: true})
			if err != nil {
				t.Fatalf("dry-run restore: %v", err)
			}
			// Zero mutations: no client was actually inserted.
			if cs, _ := dryDst.List(ctx); len(cs) != 0 {
				t.Fatalf("dry-run mutated the destination: %d clients", len(cs))
			}
			if len(dryRep.CredentialRecovery) != 0 {
				t.Fatalf("dry-run must never rotate: %+v", dryRep.CredentialRecovery)
			}
			predicted := dryRep.Items[snapshot.CategoryClients].RequiresRotation

			realDst := defaultimpl.NewMemoryClientStore()
			realRep, err := (&snapshot.Restorer{Clients: realDst}).Restore(ctx, snap, snapshot.RestoreOptions{Mode: mode})
			if err != nil {
				t.Fatalf("real restore: %v", err)
			}
			rotated := len(realRep.CredentialRecovery)
			remaining := realRep.Items[snapshot.CategoryClients].RequiresRotation
			if predicted != rotated+remaining {
				t.Errorf("dry-run predicted requires_rotation=%d, real run rotated=%d + remaining=%d", predicted, rotated, remaining)
			}
		})
	}
}

// TestRestore_RotationFailure_RecordedAndContinues proves rotation errors
// never abort the plan: the failing client is recorded in Report.Errors and
// stays counted in RequiresRotation, while the remaining clients still rotate
// and the restore completes.
func TestRestore_RotationFailure_RecordedAndContinues(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	snap := mustCodecSnapshot(t, &snapshot.Snapshot{
		SchemaVersion:   snapshot.SchemaVersion,
		SnapshotID:      "snap-fail",
		SourceNamespace: "sso-server",
		Resources: snapshot.Resources{
			Clients: []*sso.Client{mustClient("broken"), mustClient("healthy")},
		},
	})

	dst := &failingRotator{MemoryClientStore: defaultimpl.NewMemoryClientStore(), fail: "broken"}
	rep, err := (&snapshot.Restorer{Clients: dst}).Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeMerge})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if len(rep.CredentialRecovery) != 1 || rep.CredentialRecovery[0].ClientID != "healthy" {
		t.Fatalf("healthy client not rotated: %+v", rep.CredentialRecovery)
	}
	if got := rep.Items[snapshot.CategoryClients].RequiresRotation; got != 1 {
		t.Errorf("requires_rotation = %d, want 1 (broken client)", got)
	}
	var found bool
	for _, e := range rep.Errors {
		if strings.Contains(e, "broken") && strings.Contains(e, "rotate") {
			found = true
		}
	}
	if !found {
		t.Errorf("rotation failure not recorded in Report.Errors: %+v", rep.Errors)
	}
}

// failingRotator wraps MemoryClientStore and fails RotateSecret for one
// client — the Decision-1 per-client error path.
type failingRotator struct {
	*defaultimpl.MemoryClientStore
	fail string
}

func (f *failingRotator) RotateSecret(ctx context.Context, clientID string) (string, error) {
	if clientID == f.fail {
		return "", errors.New("rotate failed")
	}
	return f.MemoryClientStore.RotateSecret(ctx, clientID)
}

// TestRestore_Merge_NeverRotatesPreExistingClient proves the write-set
// guard: a Merge restore onto a destination that ALREADY has a broken
// (empty-secret) confidential client leaves it untouched — no rotation, no
// RequiresRotation count, because this restore did not write it ("leave
// existing untouched" stays intact even for broken clients).
func TestRestore_Merge_NeverRotatesPreExistingClient(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	snap := mustCodecSnapshot(t, &snapshot.Snapshot{
		SchemaVersion:   snapshot.SchemaVersion,
		SnapshotID:      "snap-merge",
		SourceNamespace: "sso-server",
		Resources: snapshot.Resources{
			Clients: []*sso.Client{mustClient("preexisting"), mustClient("fresh")},
		},
	})

	dst := defaultimpl.NewMemoryClientStore()
	if err := dst.Add(ctx, mustClient("preexisting")); err != nil {
		t.Fatalf("preseed: %v", err)
	}
	rep, err := (&snapshot.Restorer{Clients: dst}).Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeMerge})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}

	// Only the fresh client was rotated; the pre-existing broken one is not
	// the restore's doing and stays untouched.
	if len(rep.CredentialRecovery) != 1 || rep.CredentialRecovery[0].ClientID != "fresh" {
		t.Fatalf("unexpected rotation set: %+v", rep.CredentialRecovery)
	}
	if got := rep.Items[snapshot.CategoryClients].RequiresRotation; got != 0 {
		t.Errorf("requires_rotation = %d, want 0 (pre-existing client not counted)", got)
	}
	pre, err := dst.Get(ctx, "preexisting")
	if err != nil {
		t.Fatalf("get preexisting: %v", err)
	}
	if pre.Secret != "" {
		t.Errorf("pre-existing client was mutated: Secret=%q", pre.Secret)
	}
}

// TestRedactCredentialRecovery_StripsSecrets proves the ledger/audit guard:
// the persisted form carries client IDs only — the plaintext rotated secret
// exists solely in the RPC response.
func TestRedactCredentialRecovery_StripsSecrets(t *testing.T) {
	t.Parallel()
	rep := &snapshot.Report{
		CredentialRecovery: []snapshot.CredentialRecovery{
			{ClientID: "web", Secret: "top-secret-plaintext"},
		},
		MFAReenrollmentRequired: []string{"alice"},
	}
	stripped := snapshot.RedactCredentialRecovery(rep)
	if got := stripped.CredentialRecovery[0].Secret; got != "" {
		t.Errorf("stripped secret = %q, want empty", got)
	}
	if stripped.CredentialRecovery[0].ClientID != "web" {
		t.Errorf("client ID lost: %+v", stripped.CredentialRecovery[0])
	}
	// The original report (the RPC response source) is untouched.
	if rep.CredentialRecovery[0].Secret != "top-secret-plaintext" {
		t.Error("RedactCredentialRecovery mutated its input")
	}
	raw, err := json.Marshal(stripped)
	if err != nil {
		t.Fatalf("marshal stripped: %v", err)
	}
	if strings.Contains(string(raw), "top-secret-plaintext") {
		t.Error("persisted report carries the rotated secret plaintext")
	}
}
