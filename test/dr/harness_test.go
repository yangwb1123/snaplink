// Package drtest is the disaster-recovery drill harness (docs/dr-framework.md
// §6). It drives the REAL snapshot/replicate/restore machinery — no mocks —
// against t.TempDir mounts to prove the four DR-failover invariants:
//
//  1. a corrupted replica is detected and the recovery aborts before it
//     promotes onto bad data;
//  2. a replicate -> restore round-trip reproduces control-plane state;
//  3. tokens issued with the pre-failover signing keys still verify after a
//     control-plane restore (the key material is independent of the snapshot);
//  4. the audit hash chain stays continuous across a restore.
//
// The harness wires the platform/lifecycle/dr.RecoveryOrchestrator over the
// same interfaces/snapshot Snapshotter+Pipeline+Restorer the production DR
// path uses, through the orchestrator's Verifier/Promoter/Restorer seams.
package drtest

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/snapshot"
	inline "github.com/snaplink/sso/interfaces/snapshot/storageinline"
	"github.com/snaplink/sso/interfaces/sso"
	bootmem "github.com/snaplink/sso/platform/bootstrap/memory"
	"github.com/snaplink/sso/platform/lifecycle/dr"
	"github.com/snaplink/sso/platform/netpolicy"
	netmemory "github.com/snaplink/sso/platform/netpolicy/memory"
)

// stores is one control-plane backend set (clients/users/permissions/
// netpolicy/bootstrap) — the Snapshotter and Restorer both bind to one.
type stores struct {
	clients *defaultimpl.MemoryClientStore
	users   *defaultimpl.MemoryUserProvider
	perms   *permissions.MemoryProvider
	netpol  *netmemory.Store
	tracker *bootmem.Tracker
}

func newStores() *stores {
	return &stores{
		clients: defaultimpl.NewMemoryClientStore(),
		users:   defaultimpl.NewMemoryUserProvider(),
		perms:   permissions.NewMemoryProvider(),
		netpol:  netmemory.New(),
		tracker: bootmem.New(),
	}
}

func (s *stores) snapshotter() *snapshot.Snapshotter {
	return &snapshot.Snapshotter{
		Clients: s.clients, Users: s.users, Permissions: s.perms,
		NetPolicy: s.netpol, Tracker: s.tracker, Namespace: "sso-server",
	}
}

func (s *stores) restorer() *snapshot.Restorer {
	return &snapshot.Restorer{
		Clients: s.clients, Users: s.users, Permissions: s.perms,
		NetPolicy: s.netpol, Tracker: s.tracker, Namespace: "sso-server",
	}
}

// seedPrimary populates a control-plane set with a small, representative
// fixture (clients + users + roles + a menu + assignments + netpolicy +
// bootstrap version) so a round-trip has something non-trivial to reproduce.
func seedPrimary(t *testing.T, s *stores) {
	t.Helper()
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	must(s.clients.Add(ctx, &sso.Client{ID: "alpha", Name: "Alpha", Active: true, RedirectURIs: []string{"https://a.example/cb"}}))
	must(s.clients.Add(ctx, &sso.Client{ID: "beta", Name: "Beta", Active: true, RedirectURIs: []string{"https://b.example/cb"}}))
	must(s.users.CreateOrUpdate(ctx, &sso.User{ID: "u1", Email: "u1@example", CreatedAt: time.Unix(0, 0).UTC(), UpdatedAt: time.Unix(0, 0).UTC()}))
	must(s.users.CreateOrUpdate(ctx, &sso.User{ID: "u2", Email: "u2@example", CreatedAt: time.Unix(0, 0).UTC(), UpdatedAt: time.Unix(0, 0).UTC()}))
	must(s.perms.AddRole(ctx, "alpha", permissions.Role{Code: "admin", Permissions: []string{"a:*"}}))
	must(s.perms.AddRole(ctx, "alpha", permissions.Role{Code: "viewer", Permissions: []string{"a:read"}}))
	must(s.perms.AddRole(ctx, "beta", permissions.Role{Code: "writer", Permissions: []string{"b:write"}}))
	must(s.perms.SetMenus(ctx, "alpha", permissions.MenuTree{{ID: "m1", Name: "Dashboards", Path: "/d", Permission: "a:read"}}))
	must(s.perms.AssignRoles(ctx, "u1", "alpha", []string{"admin"}))
	must(s.perms.AssignRoles(ctx, "u2", "beta", []string{"writer"}))
	if _, err := s.netpol.Apply(ctx, &netpolicy.Policy{Name: "internal", CIDRs: []string{"10.0.0.0/8"}}); err != nil {
		t.Fatalf("seed netpol: %v", err)
	}
	must(s.tracker.MarkApplied(ctx, "sso-server", 2, "seed"))
}

// harness bundles the primary + DR-target control planes, the shared
// snapshot pipeline, and a replicator writing verified replicas into a
// t.TempDir DR mount.
type harness struct {
	primary    *stores
	target     *stores
	pipeline   *snapshot.Pipeline
	replicator *dr.SnapshotReplicator
	targetDir  string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	primary := newStores()
	seedPrimary(t, primary)
	target := newStores() // empty — the DR replica restores INTO this
	pipeline := &snapshot.Pipeline{}
	dir := t.TempDir()
	repl, err := dr.NewSnapshotReplicator(exportFunc(pipeline, primary.snapshotter()), dir, time.Hour, 7, nil)
	if err != nil {
		t.Fatalf("NewSnapshotReplicator: %v", err)
	}
	return &harness{primary: primary, target: target, pipeline: pipeline, replicator: repl, targetDir: dir}
}

// orchestrator wires a RecoveryOrchestrator over the harness with the REAL
// Pipeline-backed integrity + restore seams. The caller supplies the promoter
// so a test can assert whether promotion ran.
func (h *harness) orchestrator(t *testing.T, promoter dr.ReplicaPromoter) *dr.RecoveryOrchestrator {
	t.Helper()
	o, err := dr.NewRecoveryOrchestrator(dr.OrchestratorConfig{
		Replicator: h.replicator,
		Verifier:   realVerifier(h.pipeline),
		Promoter:   promoter,
		Restorer:   realRestorer(h.pipeline, h.target.restorer()),
		Readiness:  dr.NewDRReadiness(h.replicator, dr.NewRecoveryTimeTracker(0), 0, time.Hour),
		Tracker:    dr.NewRecoveryTimeTracker(0),
		RTOTarget:  time.Hour,
	})
	if err != nil {
		t.Fatalf("NewRecoveryOrchestrator: %v", err)
	}
	return o
}

// exportFunc adapts Snapshotter.Export + Pipeline.Save to dr.ExportFunc,
// mirroring cmd's buildDRExportFunc: an in-memory storage shim captures the
// sealed envelope bytes the replicator then copies to the DR mount.
func exportFunc(p *snapshot.Pipeline, s *snapshot.Snapshotter) dr.ExportFunc {
	return func(ctx context.Context) (string, []byte, error) {
		snap, err := s.Export(ctx, snapshot.ExportOptions{})
		if err != nil {
			return "", nil, err
		}
		buf := inline.New()
		if err := p.Save(ctx, snap, buf, snap.SnapshotID); err != nil {
			return "", nil, err
		}
		data, ok := buf.Bytes(snap.SnapshotID)
		if !ok {
			return "", nil, errors.New("sealed envelope missing after save")
		}
		return snap.SnapshotID, data, nil
	}
}

// realVerifier drives the ACTUAL snapshot integrity machinery: it loads the
// replica bytes through the Pipeline, whose Load recomputes + compares the
// envelope's embedded plaintext SHA-256, so a bit-flip surfaces as a load
// error and the orchestrator aborts. No mock.
func realVerifier(p *snapshot.Pipeline) dr.ReplicaIntegrityVerifier {
	return dr.VerifyReplicaFunc(func(ctx context.Context, name string, data []byte) error {
		buf := inline.New()
		if err := buf.Put(ctx, name, data); err != nil {
			return err
		}
		_, err := p.Load(ctx, buf, name)
		return err
	})
}

// realRestorer loads the replica through the Pipeline and applies it into the
// DR-target stores via the real snapshot.Restorer (merge onto the empty
// target, advancing the bootstrap tracker).
func realRestorer(p *snapshot.Pipeline, r *snapshot.Restorer) dr.StateRestorer {
	return dr.RestoreReplicaFunc(func(ctx context.Context, name string, data []byte) (string, error) {
		buf := inline.New()
		if err := buf.Put(ctx, name, data); err != nil {
			return "", err
		}
		snap, err := p.Load(ctx, buf, name)
		if err != nil {
			return "", err
		}
		rep, err := r.Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeMerge, AdvanceBootstrap: true})
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("restored %d categories", len(rep.Items)), nil
	})
}
