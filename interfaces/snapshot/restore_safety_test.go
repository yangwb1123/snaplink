package snapshot_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/interfaces/snapshot"
	storageinline "github.com/yangwb1123/snaplink/interfaces/snapshot/storageinline"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/netpolicy"
	netmemory "github.com/yangwb1123/snaplink/platform/netpolicy/memory"
	"github.com/yangwb1123/snaplink/shared/security"
)

// The D1/D2/D3 fault-injection fixtures. There is no failing in-memory
// backend anywhere in the tree, so these thin wrappers stand in for a
// backend fault (backend outage mid-restore) at exactly one seam. They
// delegate to the real memory implementations — NOT mocks.

// failFirstClientStore wraps a ClientStore whose Delete fails for the
// first failTimes calls, then behaves normally. Phase B fault injection.
type failFirstClientStore struct {
	sso.ClientStore
	failTimes int
	calls     int
}

func (s *failFirstClientStore) Delete(ctx context.Context, id string) error {
	if s.calls < s.failTimes {
		s.calls++
		return errInjectedFault
	}
	s.calls++
	return s.ClientStore.Delete(ctx, id)
}

// failFirstPermissions wraps a permissions.Provider whose AssignRoles fails
// for the first failTimes calls, then behaves normally. Phase A fault
// injection (assignments are staged in Phase A).
type failFirstPermissions struct {
	permissions.Provider
	failTimes int
	calls     int
}

func (s *failFirstPermissions) AssignRoles(ctx context.Context, userID, clientID string, roles []string) error {
	if s.calls < s.failTimes {
		s.calls++
		return errInjectedFault
	}
	s.calls++
	return s.Provider.AssignRoles(ctx, userID, clientID, roles)
}

var errInjectedFault = errors.New("injected backend fault")

// barePairwiseStore implements only the base PairwiseSubjectStore — no
// Lister/Deleter — so replace-mode preflight must reject it.
type barePairwiseStore struct{}

func (barePairwiseStore) MapPairwise(context.Context, string, string) error { return nil }
func (barePairwiseStore) LocalSubject(context.Context, string) (string, error) {
	return "", security.ErrPairwiseUnknown
}

// countingInvalidator counts control-plane invalidation probes.
type countingInvalidator struct{ n int }

func (c *countingInvalidator) InvalidateRestoredControlPlane() { c.n++ }

// --- D2: stage-then-prune fault shapes ---

// TestRestore_Replace_PhaseAFailure_ZeroDeletes pins the D2 Phase A
// contract: an injected stage failure (AssignRoles) aborts BEFORE any prune
// runs — every Deleted count is 0 and the destination is an old-state
// superset (nothing wiped). The one scoped exception is menus: replaceMenus
// wipes via SetMenus replace semantics inside Phase A, so the menus category
// may show Updated; retry converges because SetMenus is a replayable
// replace.
func TestRestore_Replace_PhaseAFailure_ZeroDeletes(t *testing.T) {
	ctx := context.Background()
	src := newFixture(t)
	snap, err := src.snapshotter().Export(ctx, snapshot.ExportOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	dst := newBlank()
	// Orphans that must survive a Phase A failure (nothing pruned).
	if err := dst.clients.Add(ctx, &sso.Client{ID: "orphan", Name: "Orphan"}); err != nil {
		t.Fatalf("preseed: %v", err)
	}
	if err := dst.users.CreateOrUpdate(ctx, &sso.User{ID: "orphan-user"}); err != nil {
		t.Fatalf("preseed: %v", err)
	}
	if _, err := dst.netpol.Apply(ctx, &netpolicy.Policy{Name: "orphan-net", CIDRs: []string{"172.16.0.0/12"}}); err != nil {
		t.Fatalf("preseed: %v", err)
	}
	dst.perms = &failFirstPermissions{Provider: dst.perms, failTimes: 1}

	rep, err := dst.restorer().Restore(ctx, snap, snapshot.RestoreOptions{
		Mode: snapshot.ModeReplace, Confirm: snap.SnapshotID,
	})
	if err == nil {
		t.Fatalf("want injected Phase A failure, got success: %+v", rep)
	}
	if rep.Committed {
		t.Error("Phase A failure must report Committed=false")
	}
	for cat, c := range rep.Items {
		if c.Deleted != 0 {
			t.Errorf("category %s reported Deleted=%d on a Phase A failure (prunes must not run)", cat, c.Deleted)
		}
	}
	// Old-state superset: orphans survive, snapshot items are present.
	if _, err := dst.clients.Get(ctx, "orphan"); err != nil {
		t.Errorf("Phase A failure pruned the orphan client: %v", err)
	}
	if _, err := dst.clients.Get(ctx, "alpha"); err != nil {
		t.Errorf("Phase A failure lost the staged client alpha: %v", err)
	}
	us, _ := dst.users.List(ctx)
	if len(us) != 3 { // orphan-user + u1 + u2
		t.Errorf("users = %d, want 3 (orphan-user must survive)", len(us))
	}
	if _, err := dst.netpol.Get(ctx, "orphan-net"); err != nil {
		t.Errorf("Phase A failure pruned the orphan netpolicy: %v", err)
	}
}

// TestRestore_Replace_PhaseBFailure_RetryConverges pins the D2 Phase B
// contract: an injected Delete failure mid-prune leaves a target-state
// superset, and re-running the SAME snapshot converges to the exact
// terminal state a healthy run reaches (byte-equal store contents).
func TestRestore_Replace_PhaseBFailure_RetryConverges(t *testing.T) {
	ctx := context.Background()
	src := newFixture(t)
	snap, err := src.snapshotter().Export(ctx, snapshot.ExportOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	// Control: a healthy replace into a fresh destination.
	control := newBlank()
	seedOrphans := func(f *fixtureBlank) {
		if err := f.clients.Add(ctx, &sso.Client{ID: "orphan", Name: "Orphan"}); err != nil {
			t.Fatalf("preseed: %v", err)
		}
		if err := f.users.CreateOrUpdate(ctx, &sso.User{ID: "orphan-user"}); err != nil {
			t.Fatalf("preseed: %v", err)
		}
		if _, err := f.netpol.Apply(ctx, &netpolicy.Policy{Name: "orphan-net", CIDRs: []string{"172.16.0.0/12"}}); err != nil {
			t.Fatalf("preseed: %v", err)
		}
	}
	seedOrphans(control)
	controlRep, err := control.restorer().Restore(ctx, snap, snapshot.RestoreOptions{
		Mode: snapshot.ModeReplace, Confirm: snap.SnapshotID,
	})
	if err != nil {
		t.Fatalf("control restore: %v", err)
	}
	if !controlRep.Committed {
		t.Error("control restore must report Committed=true")
	}

	// Faulty run: the first client Delete (the orphan) fails mid-Phase B.
	dst := newBlank()
	seedOrphans(dst)
	failing := &failFirstClientStore{ClientStore: dst.clients, failTimes: 1}
	dst.clients = failing
	rep, err := dst.restorer().Restore(ctx, snap, snapshot.RestoreOptions{
		Mode: snapshot.ModeReplace, Confirm: snap.SnapshotID,
	})
	if err == nil {
		t.Fatalf("want injected Phase B failure, got success: %+v", rep)
	}
	if rep.Committed {
		t.Error("Phase B failure must report Committed=false")
	}
	if rep.Items[snapshot.CategoryClients].Deleted != 1 {
		t.Errorf("clients Deleted=%d, want the single attempted delete", rep.Items[snapshot.CategoryClients].Deleted)
	}
	// Target superset: snapshot clients landed, the orphan is still there.
	if _, err := dst.clients.Get(ctx, "orphan"); err != nil {
		t.Errorf("orphan client deleted despite the injected Delete failure: %v", err)
	}

	// Retry with the SAME snapshot: the fault was transient (failTimes=1),
	// so the second run finishes the keep-set prune.
	retryRep, err := dst.restorer().Restore(ctx, snap, snapshot.RestoreOptions{
		Mode: snapshot.ModeReplace, Confirm: snap.SnapshotID,
	})
	if err != nil {
		t.Fatalf("retry restore: %v", err)
	}
	if !retryRep.Committed {
		t.Error("retry must converge with Committed=true")
	}
	assertSameState(t, dst, control)
}

// assertSameState compares the client/user/netpolicy contents of two
// destinations (ID-sorted, order-insensitive).
func assertSameState(t *testing.T, a, b *fixtureBlank) {
	t.Helper()
	ctx := context.Background()
	clientIDs := func(f *fixtureBlank) []string {
		cs, _ := f.clients.List(ctx)
		ids := make([]string, 0, len(cs))
		for _, c := range cs {
			ids = append(ids, c.ID)
		}
		sort.Strings(ids)
		return ids
	}
	userIDs := func(f *fixtureBlank) []string {
		us, _ := f.users.List(ctx)
		ids := make([]string, 0, len(us))
		for _, u := range us {
			ids = append(ids, u.ID)
		}
		sort.Strings(ids)
		return ids
	}
	polNames := func(f *fixtureBlank) []string {
		ps, _ := f.netpol.List(ctx)
		names := make([]string, 0, len(ps))
		for _, p := range ps {
			names = append(names, p.Name)
		}
		sort.Strings(names)
		return names
	}
	if got, want := clientIDs(a), clientIDs(b); !slicesEqual(got, want) {
		t.Errorf("client sets differ: %v vs %v", got, want)
	}
	if got, want := userIDs(a), userIDs(b); !slicesEqual(got, want) {
		t.Errorf("user sets differ: %v vs %v", got, want)
	}
	if got, want := polNames(a), polNames(b); !slicesEqual(got, want) {
		t.Errorf("netpolicy sets differ: %v vs %v", got, want)
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestRestore_Replace_PreflightCapabilityGap_ZeroWrites pins the D2
// capability preflight: a pairwise backend without Lister+Deleter is
// rejected with ErrUnsupportedRestore before anything is written.
func TestRestore_Replace_PreflightCapabilityGap_ZeroWrites(t *testing.T) {
	ctx := context.Background()
	src := newBlank()
	if err := src.clients.Add(ctx, &sso.Client{ID: "gamma", Name: "Gamma"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	src.pairwise = security.NewMemoryPairwiseSubjectStore()
	snap, err := src.snapshotter().Export(ctx, snapshot.ExportOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	dst := newBlank()
	dst.pairwise = barePairwiseStore{}
	_, err = dst.restorer().Restore(ctx, snap, snapshot.RestoreOptions{
		Mode: snapshot.ModeReplace, Confirm: snap.SnapshotID,
	})
	if !errors.Is(err, snapshot.ErrUnsupportedRestore) {
		t.Fatalf("want ErrUnsupportedRestore, got %v", err)
	}
	// Zero writes: no clients landed, no pairwise mappings, no ops side
	// effects observable at this layer.
	cs, _ := dst.clients.List(ctx)
	if len(cs) != 0 {
		t.Errorf("preflight gap still wrote clients: %v", cs)
	}
}

// --- D3: SDK validation semantics ---

// TestRestore_RollbackWithoutSafety_Rejected pins the D3 validation: rollback
// requires an explicit safety net; without it the call fails before any
// write. The validation reads the caller's RAW AutoSafetySnapshot — the
// Restorer never defaults it.
func TestRestore_RollbackWithoutSafety_Rejected(t *testing.T) {
	ctx := context.Background()
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(ctx, snapshot.ExportOptions{})

	dst := newBlank()
	_, err := dst.restorer().Restore(ctx, snap, snapshot.RestoreOptions{
		Mode: snapshot.ModeReplace, Confirm: snap.SnapshotID,
		RollbackOnError: true, // no AutoSafetySnapshot → rejected
	})
	if !errors.Is(err, snapshot.ErrRollbackWithoutSafety) {
		t.Fatalf("want ErrRollbackWithoutSafety, got %v", err)
	}
	cs, _ := dst.clients.List(ctx)
	if len(cs) != 0 {
		t.Errorf("validation failure still wrote clients: %v", cs)
	}
}

// TestRestore_RollbackIntent_PassesValidation documents the orchestrator
// boundary: a bare Restorer with RollbackOnError=true + AutoSafetySnapshot
// true validates (the flags are orchestrator intents the Restorer itself
// never implements — it applies the snapshot exactly like a plain restore;
// the orchestration that rolls back lives above it).
func TestRestore_RollbackIntent_PassesValidation(t *testing.T) {
	ctx := context.Background()
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(ctx, snapshot.ExportOptions{})

	dst := newBlank()
	rep, err := dst.restorer().Restore(ctx, snap, snapshot.RestoreOptions{
		Mode: snapshot.ModeReplace, Confirm: snap.SnapshotID,
		AutoSafetySnapshot: true,
		RollbackOnError:    true,
	})
	if err != nil {
		t.Fatalf("both-flags restore must validate and apply: %v", err)
	}
	if !rep.Committed {
		t.Error("plain restore must report Committed=true")
	}
	if rep.RolledBack || rep.SafetySnapshotID != "" {
		t.Errorf("orchestrator-only fields set by the Restorer: %+v", rep)
	}
}

// TestRestore_Committed_Semantics pins the Committed contract: true on a
// non-dry-run success, false on dry-run (predictions), and TRUE on a
// bootstrap-advance failure after the phases applied (data is applied; only
// the tracker didn't advance — callers must not key on err alone).
func TestRestore_Committed_Semantics(t *testing.T) {
	ctx := context.Background()
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(ctx, snapshot.ExportOptions{})

	// Success, non-dry-run.
	dst := newBlank()
	rep, err := dst.restorer().Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeMerge})
	if err != nil || !rep.Committed {
		t.Fatalf("merge success: rep=%+v err=%v, want Committed=true", rep, err)
	}
	// Dry-run reports false.
	dst2 := newBlank()
	rep, err = dst2.restorer().Restore(ctx, snap, snapshot.RestoreOptions{
		Mode: snapshot.ModeReplace, Confirm: snap.SnapshotID, DryRun: true,
	})
	if err != nil || rep.Committed {
		t.Fatalf("dry-run replace: rep=%+v err=%v, want Committed=false", rep, err)
	}
	// Bootstrap-advance failure after apply: Committed stays true.
	dst3 := newBlank()
	tracker := &errTracker{version: 1, markErr: errBoom} // 1 < 2 → mark attempted
	r := &snapshot.Restorer{
		Clients: dst3.clients, Users: dst3.users, Permissions: dst3.perms,
		NetPolicy: dst3.netpol, Tracker: tracker, Namespace: "sso-server",
	}
	rep, err = r.Restore(ctx, snap, snapshot.RestoreOptions{
		Mode: snapshot.ModeMerge, AdvanceBootstrap: true,
	})
	if err == nil {
		t.Fatal("want bootstrap advance error")
	}
	if !rep.Committed {
		t.Error("bootstrap-advance failure after apply must leave Committed=true")
	}
	if _, err := dst3.clients.Get(ctx, "alpha"); err != nil {
		t.Errorf("bootstrap failure must not undo applied data: %v", err)
	}
}

// --- D1: kind header / retention / capture ---

// TestPipeline_KindHeader_RoundTrip pins the D1 storage model: the kind
// lives in the SealedEnvelope HEADER (additive JSON), Save mirrors it from
// the Snapshot, Load re-attaches it, and the BODY never carries a "kind"
// key — a strict (DisallowUnknownFields) reader like a pre-change binary
// decodes the artifact byte-identically.
func TestPipeline_KindHeader_RoundTrip(t *testing.T) {
	ctx := context.Background()
	st := storageinline.New()
	p := &snapshot.Pipeline{}
	snap := &snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion, SnapshotID: "snap_kind-test",
		SourceNamespace: "ns", Kind: snapshot.KindSafetySnapshot,
	}
	if err := p.Save(ctx, snap, st, snap.SnapshotID); err != nil {
		t.Fatalf("save: %v", err)
	}
	raw, _ := st.Get(ctx, snap.SnapshotID)
	env, err := snapshot.PeekEnvelope(raw)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if env.Kind != snapshot.KindSafetySnapshot {
		t.Errorf("header kind = %q, want %q", env.Kind, snapshot.KindSafetySnapshot)
	}
	// Peek intentionally clears Body, so decode the stored envelope for the
	// old-reader simulation after checking the header-only projection.
	var stored snapshot.SealedEnvelope
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatalf("decode stored envelope: %v", err)
	}
	// Body must be byte-identical to the pre-kind era: no "kind" key.
	if bytes.Contains(stored.Body, []byte(`"kind"`)) {
		t.Error("body carries a kind key — breaks DisallowUnknownFields readers")
	}
	// Strict reader round-trip (old-binary simulation).
	var strictSnap snapshot.Snapshot
	dec := json.NewDecoder(bytes.NewReader(stored.Body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&strictSnap); err != nil {
		t.Fatalf("strict reader cannot decode the new artifact: %v", err)
	}
	// Load re-attaches the header kind for in-memory consumers.
	loaded, err := p.Load(ctx, st, snap.SnapshotID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Kind != snapshot.KindSafetySnapshot {
		t.Errorf("loaded kind = %q, want %q", loaded.Kind, snapshot.KindSafetySnapshot)
	}
	// Ordinary exports carry no kind.
	plain := &snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion, SnapshotID: "snap_plain",
		SourceNamespace: "ns",
	}
	if err := p.Save(ctx, plain, st, plain.SnapshotID); err != nil {
		t.Fatalf("save plain: %v", err)
	}
	rawPlain, _ := st.Get(ctx, plain.SnapshotID)
	envPlain, _ := snapshot.PeekEnvelope(rawPlain)
	if envPlain.Kind != "" {
		t.Errorf("ordinary export header kind = %q, want empty", envPlain.Kind)
	}
}

// TestPruneOldest_KeepsSafetyArtifacts pins the D1 retention exemption: a
// safety-kind envelope survives keep=0 (which previously deleted
// everything), while ordinary envelopes are pruned normally. The explicit
// Delete RPC is the flush path for safety artifacts.
func TestPruneOldest_KeepsSafetyArtifacts(t *testing.T) {
	ctx := context.Background()
	st := storageinline.New()
	p := &snapshot.Pipeline{}
	save := func(id, kind string) {
		t.Helper()
		snap := &snapshot.Snapshot{
			SchemaVersion: snapshot.SchemaVersion, SnapshotID: id,
			SourceNamespace: "ns", Kind: kind,
		}
		if err := p.Save(ctx, snap, st, id); err != nil {
			t.Fatalf("save %s: %v", id, err)
		}
	}
	save("snap_2026-01-01T00-00-00Z_aaa", "")                          // oldest ordinary
	save("snap_2026-01-02T00-00-00Z_bbb", snapshot.KindSafetySnapshot) // safety, middle
	save("snap_2026-01-03T00-00-00Z_ccc", "")                          // newest ordinary

	deleted, err := snapshot.PruneOldest(ctx, st, 0) // delete everything ordinary
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if len(deleted) != 2 {
		t.Errorf("deleted = %v, want the two ordinary envelopes", deleted)
	}
	remaining, _ := st.List(ctx)
	if len(remaining) != 1 || remaining[0] != "snap_2026-01-02T00-00-00Z_bbb" {
		t.Errorf("remaining = %v, want only the safety envelope", remaining)
	}
	// Explicit Delete removes it.
	if err := st.Delete(ctx, "snap_2026-01-02T00-00-00Z_bbb"); err != nil {
		t.Fatalf("delete safety: %v", err)
	}
}

// TestPruneOldest_GetErrorKeepsVictim pins the skip-on-Get-error rule: a
// transient read fault must KEEP the victim (an unclassifiable envelope is
// assumed to be a safety net) and report the fault, while other victims are
// still processed.
func TestPruneOldest_GetErrorKeepsVictim(t *testing.T) {
	ctx := context.Background()
	st := storageinline.New()
	p := &snapshot.Pipeline{}
	save := func(id string) {
		t.Helper()
		snap := &snapshot.Snapshot{
			SchemaVersion: snapshot.SchemaVersion, SnapshotID: id, SourceNamespace: "ns",
		}
		if err := p.Save(ctx, snap, st, id); err != nil {
			t.Fatalf("save: %v", err)
		}
	}
	save("snap_2026-01-01T00-00-00Z_aaa")
	save("snap_2026-01-02T00-00-00Z_bbb")
	save("snap_2026-01-03T00-00-00Z_ccc")

	flaky := &flakyGetStorage{Storage: st, failName: "snap_2026-01-01T00-00-00Z_aaa"}
	deleted, err := snapshot.PruneOldest(ctx, flaky, 1)
	if err == nil {
		t.Fatal("want the reported Get fault")
	}
	// The flaky victim is kept; the other victim is deleted.
	if len(deleted) != 1 || deleted[0] != "snap_2026-01-02T00-00-00Z_bbb" {
		t.Errorf("deleted = %v, want only the readable victim", deleted)
	}
	remaining, _ := st.List(ctx)
	if len(remaining) != 2 {
		t.Errorf("remaining = %v, want flaky victim + newest", remaining)
	}
}

// flakyGetStorage fails Get for one chosen name (transient read fault).
type flakyGetStorage struct {
	snapshot.Storage
	failName string
}

func (s *flakyGetStorage) Get(ctx context.Context, name string) ([]byte, error) {
	if name == s.failName {
		return nil, errBoom
	}
	return s.Storage.Get(ctx, name)
}

// TestCaptureSafetySnapshot_UnredactedAndRestorable pins the D1 capture
// mechanics: the explicit no-op redactor override beats a wired
// DefaultExportRedactor (the artifact stays RESTORABLE — user password
// hashes survive), the kind lands in the header, and the artifact is a
// normal restorable snapshot.
func TestCaptureSafetySnapshot_UnredactedAndRestorable(t *testing.T) {
	ctx := context.Background()
	src := newFixture(t)
	// A user with a password hash: the exact field DefaultExportRedactor
	// would scrub.
	if err := src.users.CreateOrUpdate(ctx, &sso.User{
		ID: "u3", Email: "u3@example",
		Attributes: map[string]string{"password_hash": "hash-keep-me"},
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	snapper := src.snapshotter()
	snapper.DefaultExportRedactor = snapshot.SnapshotRedactSecrets()

	st := storageinline.New()
	captured, err := snapshot.CaptureSafetySnapshot(ctx, snapper, &snapshot.Pipeline{}, st)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if captured.Kind != snapshot.KindSafetySnapshot {
		t.Errorf("captured kind = %q, want %q", captured.Kind, snapshot.KindSafetySnapshot)
	}
	env, _ := snapshot.PeekEnvelope(mustGet(t, st, captured.SnapshotID))
	if env.Kind != snapshot.KindSafetySnapshot {
		t.Errorf("header kind = %q, want safety", env.Kind)
	}
	loaded, err := (&snapshot.Pipeline{}).Load(ctx, st, captured.SnapshotID)
	if err != nil {
		t.Fatalf("load captured: %v", err)
	}
	// password_hash must survive the no-op-redactor capture.
	for _, u := range loaded.Resources.Users {
		if u.ID == "u3" && u.Attributes["password_hash"] != "hash-keep-me" {
			t.Errorf("safety capture redacted password_hash: %v", u.Attributes)
		}
	}
	// And the artifact is restorable into a fresh destination.
	dst := newBlank()
	rep, err := dst.restorer().Restore(ctx, loaded, snapshot.RestoreOptions{
		Mode: snapshot.ModeReplace, Confirm: loaded.SnapshotID,
	})
	if err != nil || !rep.Committed {
		t.Fatalf("restore from safety artifact: rep=%+v err=%v", rep, err)
	}
}

func mustGet(t *testing.T, st snapshot.Storage, name string) []byte {
	t.Helper()
	raw, err := st.Get(context.Background(), name)
	if err != nil {
		t.Fatalf("get %s: %v", name, err)
	}
	return raw
}

// TestCaptureSafetySnapshot_NilSnapshotter guards the fail-closed capture
// helper for SDK-direct callers.
func TestCaptureSafetySnapshot_NilSnapshotter(t *testing.T) {
	if _, err := snapshot.CaptureSafetySnapshot(context.Background(), nil, &snapshot.Pipeline{}, storageinline.New()); err == nil {
		t.Fatal("want error for nil snapshotter")
	}
}

// TestRollbackExcludeFor pins the D3 rollback-scope computation (security
// finding F2): the rollback re-apply must skip the caller's original
// excludes PLUS every category the failed restore's source snapshot did not
// cover — it never rewinds categories the restore never touched.
func TestRollbackExcludeFor(t *testing.T) {
	ctx := context.Background()
	src := newFixture(t)
	snap, err := src.snapshotter().Export(ctx, snapshot.ExportOptions{
		Exclude: []snapshot.ResourceCategory{snapshot.CategoryNetPolicy},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if !snap.IncludesCategory(snapshot.CategoryClients) || snap.IncludesCategory(snapshot.CategoryNetPolicy) {
		t.Fatalf("fixture precondition: categories=%v", snap.Categories)
	}
	exclude := snapshot.RollbackExcludeFor(snap, []snapshot.ResourceCategory{snapshot.CategoryUsers})
	if !snapshot.ExcludedListed(exclude, snapshot.CategoryUsers) {
		t.Error("original exclude (users) lost")
	}
	if !snapshot.ExcludedListed(exclude, snapshot.CategoryNetPolicy) {
		t.Error("source-omitted category (netpolicy) must be excluded from rollback")
	}
	if !snapshot.ExcludedListed(exclude, snapshot.CategoryTenants) ||
		!snapshot.ExcludedListed(exclude, snapshot.CategoryConnections) ||
		!snapshot.ExcludedListed(exclude, snapshot.CategoryPairwise) {
		t.Error("unwired categories must be excluded from rollback")
	}
	if snapshot.ExcludedListed(exclude, snapshot.CategoryClients) ||
		snapshot.ExcludedListed(exclude, snapshot.CategoryRoles) ||
		snapshot.ExcludedListed(exclude, snapshot.CategoryAssignments) ||
		snapshot.ExcludedListed(exclude, snapshot.CategoryMenus) {
		t.Errorf("rollback must keep categories the failed restore covered: %v", exclude)
	}
	// Input must not be mutated.
	if len(snap.Categories) == 0 {
		t.Error("input snapshot mutated")
	}
}

var _ = netmemory.New // keep import for future fixture use
