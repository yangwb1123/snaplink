package drtest

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/platform/lifecycle/dr"
)

// Scenario (a): replicate -> corrupt the replica on the DR mount -> the
// orchestrator's integrity step (real Pipeline.Load checksum) detects it and
// aborts BEFORE promotion, leaving the DR-target control plane untouched.
func TestDrill_CorruptReplicaAborts(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.replicator.ReplicateOnce(ctx); err != nil {
		t.Fatalf("ReplicateOnce: %v", err)
	}
	name, _, err := h.replicator.LatestReplica()
	if err != nil {
		t.Fatalf("LatestReplica: %v", err)
	}
	// Flip a byte deep inside the sealed envelope so it still parses as JSON
	// but fails the embedded-checksum recompute — a silent-corruption replica.
	corruptReplica(t, filepath.Join(h.targetDir, name))

	promoter := &dr.MemoryReplicaPromoter{}
	rep := h.orchestrator(t, promoter).Run(ctx)

	if rep.Succeeded {
		t.Fatal("expected the drill to abort on a corrupted replica")
	}
	if rep.AbortedAtStep != dr.StepVerifyIntegrity {
		t.Errorf("aborted at %q, want %q", rep.AbortedAtStep, dr.StepVerifyIntegrity)
	}
	if promoter.Calls() != 0 {
		t.Errorf("promotion ran %d times after integrity failure; must be 0 (a corrupted DR is worse than not failing over)", promoter.Calls())
	}
	// The DR target must be untouched — no partial restore from bad data.
	if cs, _ := h.target.clients.List(ctx); len(cs) != 0 {
		t.Errorf("DR-target clients = %d after aborted drill, want 0", len(cs))
	}
}

// Scenario (b): replicate -> restore -> the DR-target control plane reproduces
// the primary's clients + roles + assignments (round-trip fidelity through the
// real Snapshotter/Pipeline/Restorer).
func TestDrill_RestoreRoundTripMatches(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.replicator.ReplicateOnce(ctx); err != nil {
		t.Fatalf("ReplicateOnce: %v", err)
	}
	rep := h.orchestrator(t, &dr.MemoryReplicaPromoter{}).Run(ctx)
	if !rep.Succeeded {
		t.Fatalf("drill failed: %+v", rep)
	}

	assertClientsMatch(t, ctx, h)
	assertRolesMatch(t, ctx, h, "alpha")
	assertRolesMatch(t, ctx, h, "beta")

	// Bootstrap version carried across so seed steps would not re-run.
	if v, err := h.target.tracker.AppliedVersion(ctx, "sso-server"); err != nil || v != 2 {
		t.Errorf("DR-target bootstrap version = %d (err=%v), want 2", v, err)
	}
}

func assertClientsMatch(t *testing.T, ctx context.Context, h *harness) {
	t.Helper()
	src, _ := h.primary.clients.List(ctx)
	dst, _ := h.target.clients.List(ctx)
	if len(src) != len(dst) {
		t.Fatalf("client count: target=%d primary=%d", len(dst), len(src))
	}
	for _, c := range src {
		got, err := h.target.clients.Get(ctx, c.ID)
		if err != nil {
			t.Errorf("client %q missing on DR target: %v", c.ID, err)
			continue
		}
		if got.Name != c.Name {
			t.Errorf("client %q name = %q, want %q", c.ID, got.Name, c.Name)
		}
	}
}

func assertRolesMatch(t *testing.T, ctx context.Context, h *harness, clientID string) {
	t.Helper()
	src, _ := h.primary.perms.ListAllRoles(ctx, clientID)
	dst, _ := h.target.perms.ListAllRoles(ctx, clientID)
	srcCodes, dstCodes := roleCodes(src), roleCodes(dst)
	if len(srcCodes) != len(dstCodes) {
		t.Fatalf("role count for %q: target=%v primary=%v", clientID, dstCodes, srcCodes)
	}
	for i := range srcCodes {
		if srcCodes[i] != dstCodes[i] {
			t.Errorf("role[%d] for %q = %q, want %q", i, clientID, dstCodes[i], srcCodes[i])
		}
	}
}

func roleCodes(roles []permissions.Role) []string {
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		out = append(out, r.Code)
	}
	sort.Strings(out)
	return out
}

// corruptReplica flips one byte in the file so the sealed envelope's embedded
// plaintext-SHA256 no longer matches its body.
func corruptReplica(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read replica: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("replica file is empty")
	}
	// Mutate a byte near the middle (inside the base64 body, not the header
	// braces) so the file stays valid JSON but the checksum recompute fails.
	i := len(b) / 2
	b[i] ^= 0xff
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write corrupted replica: %v", err)
	}
}
