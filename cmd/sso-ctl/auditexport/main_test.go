package auditexport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/infrastructure/auditgovernance"
	"github.com/yangwb1123/snaplink/infrastructure/auditoutbox"
	"github.com/yangwb1123/snaplink/platform/audit"
	libexport "github.com/yangwb1123/snaplink/platform/audit/auditexport"
	auditsqlite "github.com/yangwb1123/snaplink/platform/audit/sqlite"
	"github.com/yangwb1123/snaplink/shared/core"
)

// seedStore records n hash-chained events into a fresh SQLite audit
// store at dsn and closes it, leaving a durable chain for the CLI to
// export. The optional event type defaults to login; token-issue tests
// pass audit.EventTokenIssued to pin the registry-driven filter path.
func seedStore(t *testing.T, dsn string, n int, typ ...audit.EventType) {
	t.Helper()
	et := audit.EventLogin
	if len(typ) > 0 {
		et = typ[0]
	}
	sink, err := auditsqlite.New(dsn)
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	defer func() { _ = sink.Close() }()
	base := time.Unix(1700000000, 0).UTC()
	i := 0
	r := audit.New(sink, audit.WithHashChain(), audit.WithClock(func() time.Time {
		i++
		return base.Add(time.Duration(i) * time.Hour)
	}))
	for k := 0; k < n; k++ {
		r.Record(context.Background(), &audit.Event{Type: et, Outcome: audit.OutcomeSuccess, ActorID: "user"})
	}
}

func TestRun_ExportToFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	out := filepath.Join(dir, "evidence.json")
	seedStore(t, dsn, 5)

	code := captureQuiet(t, func() int { return Run([]string{"--dsn", dsn, "--out", out}) })
	if code != 0 {
		t.Fatalf("Run exit=%d, want 0", code)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	// AC-7: an unanchored bundle is byte-identical to the legacy output —
	// the additive anchor key must be absent (omitempty).
	if strings.Contains(string(raw), "\"anchor\"") {
		t.Errorf("unanchored bundle JSON must not carry an anchor key")
	}
	var b libexport.ExportBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}
	if b.EventCount != 5 {
		t.Fatalf("EventCount=%d, want 5", b.EventCount)
	}
	if err := libexport.VerifyExportBundle(&b); err != nil {
		t.Errorf("on-disk bundle failed verify: %v", err)
	}
}

func TestRun_ExportToStdout(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	seedStore(t, dsn, 3)

	var code int
	out := captureStdout(t, func() { code = Run([]string{"--dsn", dsn}) })
	if code != 0 {
		t.Fatalf("Run exit=%d, want 0", code)
	}
	var b libexport.ExportBundle
	if err := json.Unmarshal([]byte(out), &b); err != nil {
		t.Fatalf("stdout is not a JSON bundle: %v\n%s", err, out)
	}
	if b.EventCount != 3 {
		t.Fatalf("EventCount=%d, want 3", b.EventCount)
	}
	if err := libexport.VerifyExportBundle(&b); err != nil {
		t.Errorf("stdout bundle failed verify: %v", err)
	}
}

func TestRun_EmptyWindowExitsZero(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	out := filepath.Join(dir, "empty.json")
	seedStore(t, dsn, 3)

	code := captureQuiet(t, func() int {
		return Run([]string{"--dsn", dsn, "--since", "2100-01-01T00:00:00Z", "--out", out})
	})
	if code != 0 {
		t.Fatalf("Run exit=%d, want 0 for an empty window", code)
	}
	raw, _ := os.ReadFile(out)
	var b libexport.ExportBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if b.EventCount != 0 {
		t.Fatalf("EventCount=%d, want 0", b.EventCount)
	}
}

func TestRun_TenantAndTypeFilter(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	out := filepath.Join(dir, "filtered.json")
	seedStore(t, dsn, 4)

	var code int
	stderr := captureStderr(t, func() {
		code = Run([]string{"--dsn", dsn, "--type", string(audit.EventLogout), "--out", out})
	})
	if code != 0 {
		t.Fatalf("Run exit=%d, want 0", code)
	}
	// logout is a registered type: the empty result must stay silent — the
	// distinction between a genuinely empty window (exit 0, fine) and a
	// mistyped filter (diagnostic, never silent).
	if strings.Contains(stderr, "not a registered sso event type") {
		t.Errorf("registered type %q must not warn:\n%s", audit.EventLogout, stderr)
	}
	raw, _ := os.ReadFile(out)
	var b libexport.ExportBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// No logout events were seeded → empty, and a filtered bundle is
	// marked non-contiguous.
	if b.Contiguous {
		t.Error("type-filtered bundle should be non-contiguous")
	}
	if err := libexport.VerifyExportBundle(&b); err != nil {
		t.Errorf("filtered bundle failed verify: %v", err)
	}
}

// TestValidateOutcome pins the closed --outcome vocabulary: empty is the
// wildcard, success/failure are the only legal values, and matching is
// exact (no case folding, no trimming) like the store's literal match.
func TestValidateOutcome(t *testing.T) {
	for _, tc := range []struct {
		value string
		ok    bool
	}{
		{"", true},
		{"success", true},
		{"failure", true},
		{"bogus", false},
		{"Success", false},
		{" success", false},
	} {
		err := validateOutcome(tc.value)
		if (err == nil) != tc.ok {
			t.Errorf("validateOutcome(%q) err=%v, want ok=%v", tc.value, err, tc.ok)
		}
	}
}

// TestRun_UnknownOutcomeExitsTwo pins AC-1a: an unknown --outcome is CLI
// misuse — exit 2, a diagnostic naming the value and the allowed set, no
// type warning (outcome dominates), and no bundle file (validation
// precedes any store open / write).
func TestRun_UnknownOutcomeExitsTwo(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	out := filepath.Join(dir, "evidence.json")
	seedStore(t, dsn, 3)

	var code int
	stderr := captureStderr(t, func() {
		code = Run([]string{"--dsn", dsn, "--outcome", "bogus", "--type", "bogus", "--out", out})
	})
	if code != 2 {
		t.Fatalf("Run exit=%d, want 2", code)
	}
	for _, want := range []string{"not a valid outcome (allowed: success|failure)", "--outcome", "bogus"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr)
		}
	}
	if strings.Contains(stderr, "not a registered sso event type") {
		t.Errorf("type warning must not fire before the outcome misuse:\n%s", stderr)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("bundle file must not exist after misuse, stat err=%v", err)
	}
}

// TestRun_UnknownOutcomeVerifyModeExitsTwo pins row 2 of the failure
// table: validation precedes the mode branch. A nonexistent bundle path
// would make runVerify fail with exit 1 — exit 2 proves --outcome is
// rejected before --verify is even touched.
func TestRun_UnknownOutcomeVerifyModeExitsTwo(t *testing.T) {
	var code int
	stderr := captureStderr(t, func() {
		code = Run([]string{"--verify", filepath.Join(t.TempDir(), "nope.json"), "--outcome", "bogus"})
	})
	if code != 2 {
		t.Fatalf("Run exit=%d, want 2 (validation must precede the mode branch)", code)
	}
	if !strings.Contains(stderr, "not a valid outcome") {
		t.Errorf("stderr missing outcome diagnostic:\n%s", stderr)
	}
}

// TestRun_UnknownOutcomeBeatsMutuallyExclusive pins the three-way
// double-misuse corner: with --verify, --dsn AND an unknown --outcome,
// the outcome diagnostic (exit 2 + banner) wins over the "mutually
// exclusive" message because validateOutcome runs before the exclusivity
// check. The message, not the exit class, is the discriminator.
func TestRun_UnknownOutcomeBeatsMutuallyExclusive(t *testing.T) {
	var code int
	stderr := captureStderr(t, func() {
		code = Run([]string{"--verify", filepath.Join(t.TempDir(), "nope.json"), "--dsn", "x.db", "--outcome", "bogus"})
	})
	if code != 2 {
		t.Fatalf("Run exit=%d, want 2", code)
	}
	if !strings.Contains(stderr, "not a valid outcome") {
		t.Errorf("stderr missing outcome diagnostic:\n%s", stderr)
	}
	if strings.Contains(stderr, "mutually exclusive") {
		t.Errorf("outcome diagnostic must precede the exclusivity check:\n%s", stderr)
	}
}

// TestRun_MissingDSNExitsTwo pins the refactored usage-error branch:
// neither --dsn nor --verify is a usage error — exit 2 with the banner,
// no store or bundle side effects.
func TestRun_MissingDSNExitsTwo(t *testing.T) {
	var code int
	stderr := captureStderr(t, func() { code = Run(nil) })
	if code != 2 {
		t.Fatalf("Run exit=%d, want 2", code)
	}
	if !strings.Contains(stderr, "required") || !strings.Contains(stderr, progName) {
		t.Errorf("stderr missing usage diagnostic + banner:\n%s", stderr)
	}
}

// TestRun_UnknownTypeWarnsAndStillExports pins AC-1b: an unknown --type
// is advisory — stderr warning naming the value, exit 0, bundle written
// and verified (empty, but no longer silent). Custom event types are
// legal per EventType's doc.
func TestRun_UnknownTypeWarnsAndStillExports(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	out := filepath.Join(dir, "evidence.json")
	seedStore(t, dsn, 3)

	var code int
	stderr := captureStderr(t, func() {
		code = Run([]string{"--dsn", dsn, "--type", "not_a_real_type", "--out", out})
	})
	if code != 0 {
		t.Fatalf("Run exit=%d, want 0 (custom types are legal; warning only)", code)
	}
	if !strings.Contains(stderr, "warning") || !strings.Contains(stderr, "not_a_real_type") {
		t.Errorf("stderr missing type warning:\n%s", stderr)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	var b libexport.ExportBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if b.EventCount != 0 {
		t.Fatalf("EventCount=%d, want 0", b.EventCount)
	}
	if err := libexport.VerifyExportBundle(&b); err != nil {
		t.Errorf("bundle failed verify: %v", err)
	}
}

// TestRun_TokenTypeFilterExportsAndVerifies pins AC-3 with today's token
// vocabulary: token_issued is registered, so the filter must be silent
// and export exactly the seeded events. When B4-5 registers
// auth.token.issue, this test extends with that constant and the CLI
// needs zero changes (registry-driven, R-3).
func TestRun_TokenTypeFilterExportsAndVerifies(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	out := filepath.Join(dir, "evidence.json")
	const n = 4
	seedStore(t, dsn, n, audit.EventTokenIssued)

	var code int
	stderr := captureStderr(t, func() {
		code = Run([]string{"--dsn", dsn, "--type", string(audit.EventTokenIssued), "--out", out})
	})
	if code != 0 {
		t.Fatalf("Run exit=%d, want 0", code)
	}
	if strings.Contains(stderr, "not a registered sso event type") {
		t.Errorf("registered type %q must not warn:\n%s", audit.EventTokenIssued, stderr)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	var b libexport.ExportBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if b.EventCount != n {
		t.Fatalf("EventCount=%d, want %d", b.EventCount, n)
	}
	if err := libexport.VerifyExportBundle(&b); err != nil {
		t.Errorf("bundle failed verify: %v", err)
	}
}

func TestRun_OpenErrorExitsOne(t *testing.T) {
	// A read-only DSN pointed at a missing file fails to open.
	dsn := "file:" + filepath.Join(t.TempDir(), "missing.db") + "?mode=ro"
	code, err := run(options{dsn: dsn})
	if code != 1 || err == nil {
		t.Fatalf("run over missing ro db: code=%d err=%v, want (1, err)", code, err)
	}
}

// TestRun_ExportModeROSucceeds proves the old failure mode is gone: a
// ?mode=ro DSN against an EXISTING store used to fail ("readonly
// database") because the constructor ran migrate.Run's BEGIN IMMEDIATE.
// OpenReadOnly never migrates, so the export now runs.
func TestRun_ExportModeROSucceeds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.db")
	out := filepath.Join(dir, "evidence.json")
	seedStore(t, path, 4)

	code := captureQuiet(t, func() int {
		return Run([]string{"--dsn", "file:" + path + "?mode=ro", "--out", out})
	})
	if code != 0 {
		t.Fatalf("export over ?mode=ro exit=%d, want 0", code)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	var b libexport.ExportBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if b.EventCount != 4 {
		t.Fatalf("EventCount=%d, want 4", b.EventCount)
	}
}

// TestRun_ExportDoesNotModifyStore asserts the export is read-only at the
// file level: the db file is byte-identical before and after, so the tool
// neither takes a write lock nor mutates the schema of a live store.
func TestRun_ExportDoesNotModifyStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.db")
	out := filepath.Join(dir, "evidence.json")
	seedStore(t, path, 6)
	before := hashFile(t, path)

	code := captureQuiet(t, func() int { return Run([]string{"--dsn", "file:" + path, "--out", out}) })
	if code != 0 {
		t.Fatalf("export exit=%d, want 0", code)
	}
	if after := hashFile(t, path); after != before {
		t.Fatalf("export mutated the db file: hash %s -> %s", before, after)
	}
}

// TestRunVerify_Pass round-trips through the offline-verify verb: export a
// bundle, then verify the finished file with no store access. The stderr
// capture pins the R-6 negative: the unanchored OK line must not carry an
// anchor_head= field (it appears only when an anchor was enforced).
func TestRunVerify_Pass(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.db")
	out := filepath.Join(dir, "evidence.json")
	seedStore(t, path, 5)
	if code := captureQuiet(t, func() int { return Run([]string{"--dsn", path, "--out", out}) }); code != 0 {
		t.Fatalf("export exit=%d", code)
	}

	var code int
	stderr := captureStderr(t, func() { code, _ = runVerify(out, "") })
	if code != 0 {
		t.Fatalf("runVerify(clean) = (%d), want 0", code)
	}
	if strings.Contains(stderr, "anchor_head=") {
		t.Errorf("unanchored OK line must not name an anchor head:\n%s", stderr)
	}
}

// TestRunVerify_TamperFails proves a byte-flipped event in the bundle file
// makes offline verify exit non-zero with a message, and (AC-3) that a
// valid anchor cannot rescue the tampered bundle: VerifyExportBundle runs
// first, so the reported failure is the chain check, not anchor
// enforcement (F7).
func TestRunVerify_TamperFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.db")
	out := filepath.Join(dir, "evidence.json")
	cpPath := filepath.Join(dir, "cp.json")
	seedStore(t, path, 5)
	if code := captureQuiet(t, func() int { return Run([]string{"--dsn", path, "--out", out}) }); code != 0 {
		t.Fatalf("export exit=%d", code)
	}
	cp, _ := checkpointAtHead(t, path)
	writeCheckpoint(t, cpPath, cp)

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	var b libexport.ExportBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// ActorID is a hashed field (eventHash covers every field but ID/Hash),
	// so mutating it in a middle event breaks chain-segment verification.
	b.Events[2].ActorID = "tampered"
	tampered, err := json.Marshal(&b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(out, tampered, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	code, err := runVerify(out, "")
	if code == 0 || err == nil {
		t.Fatalf("runVerify(tampered) = (%d, %v), want non-zero + error", code, err)
	}
	// AC-3: the same tampered bundle with a valid matching --anchor still
	// fails, and the reported failure is the bundle check, not the anchor.
	var anchored int
	stderr := captureStderr(t, func() { anchored = Run([]string{"--verify", out, "--anchor", cpPath}) })
	if anchored == 0 {
		t.Fatal("anchored verify of a tampered bundle must fail — the anchor cannot rescue it")
	}
	if !strings.Contains(stderr, "bundle FAILED verification") {
		t.Errorf("anchored tamper must report the chain check, got:\n%s", stderr)
	}
}

// TestRunVerify_MissingFile exits non-zero on a bundle path that does not
// exist.
func TestRunVerify_MissingFile(t *testing.T) {
	code, err := runVerify(filepath.Join(t.TempDir(), "nope.json"), "")
	if code != 1 || err == nil {
		t.Fatalf("runVerify(missing) = (%d, %v), want (1, err)", code, err)
	}
}

// hashFile returns a hex SHA-256 of the db file so a read-only open can be
// asserted byte-preserving.
func hashFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read db file: %v", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// writeCheckpoint marshals a signed checkpoint to path as JSON — the file
// form the --anchor flag consumes.
func writeCheckpoint(t *testing.T, path string, cp *audit.SignedCheckpoint) {
	t.Helper()
	raw, err := json.Marshal(cp)
	if err != nil {
		t.Fatalf("marshal checkpoint: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write checkpoint: %v", err)
	}
}

// checkpointAtHead produces a REAL signed checkpoint for the seeded chain:
// the genuine notary over the sqlite sink (whose LastHash is the exported
// head). Returns the signer too so tests can re-sign modified checkpoints
// (the AC-1 isolation trick: a validly-signed stale head isolates head
// mismatch from signature failure).
func checkpointAtHead(t *testing.T, dsn string) (*audit.SignedCheckpoint, audit.CheckpointSigner) {
	t.Helper()
	sink, err := auditsqlite.OpenReadOnly(dsn)
	if err != nil {
		t.Fatalf("open for notary: %v", err)
	}
	defer func() { _ = sink.Close() }()
	signer, err := audit.NewEd25519CheckpointSigner()
	if err != nil {
		t.Fatal(err)
	}
	notary := audit.NewNotary(sink, audit.NewMemoryCheckpointStore(), signer, time.Hour, nil, nil)
	cp, err := notary.CheckpointNow(context.Background())
	if err != nil {
		t.Fatalf("CheckpointNow: %v", err)
	}
	if cp == nil {
		t.Fatal("no checkpoint produced for a non-empty chain")
	}
	return cp, signer
}

// resignCheckpoint re-signs a copy of cp with the given signer over a
// modified Checkpoint, keeping the attestation signature-valid (the
// load-bearing part of the AC-1 isolation trick).
func resignCheckpoint(t *testing.T, cp *audit.SignedCheckpoint, head string, signer audit.CheckpointSigner) *audit.SignedCheckpoint {
	t.Helper()
	mut := *cp
	mut.Checkpoint.HeadHash = head
	raw, err := json.Marshal(mut.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	mut.Signature = sig
	mut.SignerKey = signer.PublicKey()
	return &mut
}

// genesisCheckpoint self-signs a checkpoint attesting GenesisHash — the
// R-5 empty-bundle anchor. Test/pilot-only construction: the genuine
// notary never issues one for an empty store (an empty head equals its
// lastSigned sentinel, so CheckpointNow suppresses it).
func genesisCheckpoint(t *testing.T) *audit.SignedCheckpoint {
	t.Helper()
	signer, err := audit.NewEd25519CheckpointSigner()
	if err != nil {
		t.Fatal(err)
	}
	cp := audit.Checkpoint{Sequence: 1, Timestamp: time.Now().UTC(), HeadHash: audit.GenesisHash}
	raw, err := json.Marshal(cp)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	return &audit.SignedCheckpoint{Checkpoint: cp, Signature: sig, SignerKey: signer.PublicKey()}
}

// TestRunVerify_AnchorMismatchExitsOne (AC-1) pins the verify-mode anchor
// contract: an explicitly flagged checkpoint whose attested head differs
// from the bundle head exits 1 naming BOTH hashes, while the genuine
// matching checkpoint exits 0 and the OK line names the enforced anchor
// head (R-6 positive). The stale checkpoint is re-signed by the same
// signer, so the failure isolates head mismatch from signature failure.
func TestRunVerify_AnchorMismatchExitsOne(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	evidence := filepath.Join(dir, "evidence.json")
	cpPath := filepath.Join(dir, "cp.json")
	cpStalePath := filepath.Join(dir, "cp-stale.json")
	seedStore(t, dsn, 5)
	if code := captureQuiet(t, func() int { return Run([]string{"--dsn", dsn, "--out", evidence}) }); code != 0 {
		t.Fatalf("export exit=%d", code)
	}
	cp, signer := checkpointAtHead(t, dsn)
	writeCheckpoint(t, cpPath, cp)

	raw, err := os.ReadFile(evidence)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	var b libexport.ExportBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	writeCheckpoint(t, cpStalePath, resignCheckpoint(t, cp, b.Events[0].Hash, signer))

	var code int
	stderr := captureStderr(t, func() { code = Run([]string{"--verify", evidence, "--anchor", cpStalePath}) })
	if code != 1 {
		t.Fatalf("stale-head anchor exit=%d, want 1", code)
	}
	if !strings.Contains(stderr, b.HeadHash) || !strings.Contains(stderr, b.Events[0].Hash) {
		t.Errorf("stderr must name both hashes (bundle head %q, attestation %q):\n%s", b.HeadHash, b.Events[0].Hash, stderr)
	}

	// Positive control: the genuine checkpoint verifies, and the OK line
	// names the enforced anchor head (R-6 positive).
	var ok int
	okStderr := captureStderr(t, func() { ok = Run([]string{"--verify", evidence, "--anchor", cpPath}) })
	if ok != 0 {
		t.Fatalf("genuine anchor exit=%d, want 0", ok)
	}
	if want := "anchor_head=" + cp.Checkpoint.HeadHash; !strings.Contains(okStderr, want) {
		t.Errorf("OK line missing %q:\n%s", want, okStderr)
	}
}

// TestRun_ExportAnchoredBundleEmbedsCheckpoint (AC-2) pins the export-mode
// anchor contract: a genuine checkpoint embeds into the bundle (head
// equality holds), the embedded copy keeps its valid signature through the
// JSON round trip, and a later --verify with no flag takes the embedded
// path with the convenience warning.
func TestRun_ExportAnchoredBundleEmbedsCheckpoint(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	out := filepath.Join(dir, "evidence.json")
	cpPath := filepath.Join(dir, "cp.json")
	seedStore(t, dsn, 5)
	cp, _ := checkpointAtHead(t, dsn)
	writeCheckpoint(t, cpPath, cp)

	code := captureQuiet(t, func() int { return Run([]string{"--dsn", dsn, "--anchor", cpPath, "--out", out}) })
	if code != 0 {
		t.Fatalf("anchored export exit=%d, want 0", code)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	var b libexport.ExportBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if b.Anchor == nil {
		t.Fatal("bundle must embed the signed checkpoint")
	}
	if err := audit.VerifyCheckpointSignature(b.Anchor); err != nil {
		t.Errorf("embedded checkpoint signature invalid after round trip: %v", err)
	}
	if b.Anchor.Checkpoint.HeadHash != b.HeadHash {
		t.Errorf("embedded attestation %q != bundle head %q", b.Anchor.Checkpoint.HeadHash, b.HeadHash)
	}

	// Embedded-anchor verify path: no flag, exit 0, with the §3.2 warning
	// distinguishing convenience from enforcement-grade.
	var v int
	vStderr := captureStderr(t, func() { v, _ = runVerify(out, "") })
	if v != 0 {
		t.Fatalf("embedded-anchor verify exit=%d, want 0", v)
	}
	if !strings.Contains(vStderr, "anchor_head="+b.Anchor.Checkpoint.HeadHash) {
		t.Errorf("embedded verify must name the anchor head:\n%s", vStderr)
	}
	if !strings.Contains(vStderr, "warning=embedded-anchor-not-enforcement-grade") {
		t.Errorf("embedded-only verify must carry the convenience warning:\n%s", vStderr)
	}
}

// TestRun_AnchorForgedSignatureExitsOne (AC-4 / F3) pins that signature
// validity is enforced, not just head equality: a checkpoint with an
// otherwise-matching head but a signature that does not verify fails in
// both modes, and the export attempt writes no bundle.
func TestRun_AnchorForgedSignatureExitsOne(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	out := filepath.Join(dir, "evidence.json")
	forgedPath := filepath.Join(dir, "forged.json")
	seedStore(t, dsn, 5)
	cp, _ := checkpointAtHead(t, dsn)
	// notary_test.go:123-127 forger pattern: a wrong key signing unrelated
	// bytes over an otherwise matching checkpoint.
	forger, err := audit.NewEd25519CheckpointSigner()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := forger.Sign([]byte("forged"))
	if err != nil {
		t.Fatal(err)
	}
	writeCheckpoint(t, forgedPath, &audit.SignedCheckpoint{Checkpoint: cp.Checkpoint, Signature: sig, SignerKey: forger.PublicKey()})

	var code int
	stderr := captureStderr(t, func() { code = Run([]string{"--dsn", dsn, "--anchor", forgedPath, "--out", out}) })
	if code != 1 {
		t.Fatalf("forged-anchor export exit=%d, want 1", code)
	}
	if !strings.Contains(stderr, "FAILED signature check") {
		t.Errorf("export stderr missing signature diagnostic:\n%s", stderr)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("no bundle file may be written after a signature failure, stat err=%v", err)
	}

	evidence := filepath.Join(dir, "evidence.json")
	if code := captureQuiet(t, func() int { return Run([]string{"--dsn", dsn, "--out", evidence}) }); code != 0 {
		t.Fatalf("export exit=%d", code)
	}
	var vcode int
	vStderr := captureStderr(t, func() { vcode = Run([]string{"--verify", evidence, "--anchor", forgedPath}) })
	if vcode != 1 {
		t.Fatalf("forged-anchor verify exit=%d, want 1", vcode)
	}
	if !strings.Contains(vStderr, "FAILED signature check") {
		t.Errorf("verify stderr missing signature diagnostic:\n%s", vStderr)
	}
}

// TestRun_ExportAnchorHeadMismatchExitsOne (AC-5 / F4, R-5) pins the
// fail-closed export: an anchor attesting an earlier head exits 1 naming
// both hashes and leaves no bundle file; a genesis-anchored empty window
// exits 0 (the empty bundle's "" equals GenesisHash).
func TestRun_ExportAnchorHeadMismatchExitsOne(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	evidence := filepath.Join(dir, "evidence.json")
	stalePath := filepath.Join(dir, "stale.json")
	out := filepath.Join(dir, "mismatch.json")
	seedStore(t, dsn, 5)
	cp, signer := checkpointAtHead(t, dsn)

	if code := captureQuiet(t, func() int { return Run([]string{"--dsn", dsn, "--out", evidence}) }); code != 0 {
		t.Fatalf("export exit=%d", code)
	}
	raw, err := os.ReadFile(evidence)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	var b libexport.ExportBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	writeCheckpoint(t, stalePath, resignCheckpoint(t, cp, b.Events[0].Hash, signer))

	var code int
	stderr := captureStderr(t, func() { code = Run([]string{"--dsn", dsn, "--anchor", stalePath, "--out", out}) })
	if code != 1 {
		t.Fatalf("stale-anchor export exit=%d, want 1", code)
	}
	if !strings.Contains(stderr, b.HeadHash) || !strings.Contains(stderr, b.Events[0].Hash) {
		t.Errorf("stderr must name both hashes:\n%s", stderr)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("no bundle file may be written on head mismatch, stat err=%v", err)
	}

	// R-5: genesis-anchored empty window exports cleanly.
	genesisPath := filepath.Join(dir, "genesis.json")
	writeCheckpoint(t, genesisPath, genesisCheckpoint(t))
	emptyOut := filepath.Join(dir, "empty.json")
	if code := captureQuiet(t, func() int {
		return Run([]string{"--dsn", dsn, "--since", "2100-01-01T00:00:00Z", "--anchor", genesisPath, "--out", emptyOut})
	}); code != 0 {
		t.Fatalf("genesis-anchored empty export exit=%d, want 0", code)
	}
}

// TestRunVerify_ConflictingAnchorsExitsOne (AC-6 / F6) pins flag-wins
// resolution: a byte-differing embedded anchor plus flag exits 1 with the
// conflicting-anchors diagnostic (CheckpointEqual is full-JSON byte
// equality — a re-issued checkpoint with the same head still differs), and
// the byte-identical checkpoint file verifies cleanly.
func TestRunVerify_ConflictingAnchorsExitsOne(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	out := filepath.Join(dir, "evidence.json")
	cp1Path := filepath.Join(dir, "cp1.json")
	cp2Path := filepath.Join(dir, "cp2.json")
	seedStore(t, dsn, 5)
	cp1, _ := checkpointAtHead(t, dsn)
	writeCheckpoint(t, cp1Path, cp1)
	if code := captureQuiet(t, func() int { return Run([]string{"--dsn", dsn, "--anchor", cp1Path, "--out", out}) }); code != 0 {
		t.Fatalf("anchored export exit=%d", code)
	}
	// A fresh notary re-issues the same head with a new sequence/timestamp
	// (NewNotary resets lastSeq/lastSigned), so cp2 differs byte-wise from
	// the embedded cp1 even though it attests the same head.
	cp2, _ := checkpointAtHead(t, dsn)
	writeCheckpoint(t, cp2Path, cp2)

	var code int
	stderr := captureStderr(t, func() { code = Run([]string{"--verify", out, "--anchor", cp2Path}) })
	if code != 1 {
		t.Fatalf("conflicting anchors exit=%d, want 1", code)
	}
	if !strings.Contains(stderr, "conflicting anchors") {
		t.Errorf("stderr missing conflicting-anchors diagnostic:\n%s", stderr)
	}

	// The byte-identical checkpoint file is the canonical operator path.
	if code := Run([]string{"--verify", out, "--anchor", cp1Path}); code != 0 {
		t.Fatalf("byte-identical anchor exit=%d, want 0", code)
	}
}

// TestRun_AnchorFileErrors (AC-10 / F1-F2) is table-driven: missing and
// unreadable anchor files exit 1 with "read anchor <path>", malformed JSON
// exits 1 with "parse anchor <path>", in both modes, and export rows
// leave no bundle file behind (fail-fast precedes the store open).
func TestRun_AnchorFileErrors(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	seedStore(t, dsn, 3)
	missing := filepath.Join(dir, "nope.json")
	unreadable := dir // a directory: ReadFile always fails regardless of privileges
	malformed := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(malformed, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, anchor, want string
	}{
		{"missing", missing, "read anchor " + missing},
		{"unreadable", unreadable, "read anchor " + unreadable},
		{"malformed", malformed, "parse anchor " + malformed},
	} {
		t.Run(tc.name+"/export", func(t *testing.T) {
			out := filepath.Join(dir, "out-"+tc.name+".json")
			var code int
			stderr := captureStderr(t, func() { code = Run([]string{"--dsn", dsn, "--anchor", tc.anchor, "--out", out}) })
			if code != 1 {
				t.Fatalf("exit=%d, want 1", code)
			}
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("stderr missing %q:\n%s", tc.want, stderr)
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatalf("no bundle file may be written, stat err=%v", err)
			}
		})
		t.Run(tc.name+"/verify", func(t *testing.T) {
			bundle := filepath.Join(dir, "bundle.json")
			if code := captureQuiet(t, func() int { return Run([]string{"--dsn", dsn, "--out", bundle}) }); code != 0 {
				t.Fatalf("export exit=%d", code)
			}
			var code int
			stderr := captureStderr(t, func() { code = Run([]string{"--verify", bundle, "--anchor", tc.anchor}) })
			if code != 1 {
				t.Fatalf("exit=%d, want 1", code)
			}
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("stderr missing %q:\n%s", tc.want, stderr)
			}
		})
	}
}

// TestRun_EmptyBundleAnchor (AC-11 / F8-F9, R-5) is table-driven: an empty
// bundle anchored by a genesis checkpoint passes in both modes, and a
// non-genesis anchor fails closed in both modes naming both hashes — the
// same single enforceAnchorHead check covers the empty case (no special
// case in code).
func TestRun_EmptyBundleAnchor(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	seedStore(t, dsn, 3)
	genesisPath := filepath.Join(dir, "genesis.json")
	writeCheckpoint(t, genesisPath, genesisCheckpoint(t))
	headPath := filepath.Join(dir, "head.json")
	cp, _ := checkpointAtHead(t, dsn)
	writeCheckpoint(t, headPath, cp)

	// Export rows: anchored empty-window export.
	for _, tc := range []struct {
		name, anchor string
		wantCode     int
	}{
		{"genesis", genesisPath, 0},
		{"non-genesis", headPath, 1},
	} {
		t.Run(tc.name+"/export", func(t *testing.T) {
			out := filepath.Join(dir, "empty-"+tc.name+".json")
			var code int
			stderr := captureStderr(t, func() {
				code = Run([]string{"--dsn", dsn, "--since", "2100-01-01T00:00:00Z", "--anchor", tc.anchor, "--out", out})
			})
			if code != tc.wantCode {
				t.Fatalf("exit=%d, want %d", code, tc.wantCode)
			}
			if tc.wantCode == 1 && !strings.Contains(stderr, "anchor head mismatch") {
				t.Errorf("stderr missing head-mismatch diagnostic:\n%s", stderr)
			}
		})
	}

	// Verify rows: an unanchored empty bundle verified against each anchor.
	empty := filepath.Join(dir, "empty.json")
	if code := captureQuiet(t, func() int {
		return Run([]string{"--dsn", dsn, "--since", "2100-01-01T00:00:00Z", "--out", empty})
	}); code != 0 {
		t.Fatalf("empty export exit=%d", code)
	}
	for _, tc := range []struct {
		name, anchor string
		wantCode     int
	}{
		{"genesis", genesisPath, 0},
		{"non-genesis", headPath, 1},
	} {
		t.Run(tc.name+"/verify", func(t *testing.T) {
			var code int
			stderr := captureStderr(t, func() { code = Run([]string{"--verify", empty, "--anchor", tc.anchor}) })
			if code != tc.wantCode {
				t.Fatalf("exit=%d, want %d", code, tc.wantCode)
			}
			if tc.wantCode == 1 && !strings.Contains(stderr, "anchor head mismatch") {
				t.Errorf("stderr missing head-mismatch diagnostic:\n%s", stderr)
			}
		})
	}
}

// TestRun_ExportMidChainWindowAnchorExitsOne (AC-12 / F11) pins the
// intended fail-closed semantics for an export whose tail is not the
// chain head: a mid-chain time window (--until before the last seeded
// event) ends at an interior hash, which NO genuine checkpoint can ever
// attest (checkpoints attest chain heads only), so the anchored export
// exits 1 and writes no bundle. Note: --limit is NOT this case — pageAll
// caps the NEWEST tail, so a limited export still ends at the chain head
// and can be anchored.
func TestRun_ExportMidChainWindowAnchorExitsOne(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	out := filepath.Join(dir, "evidence.json")
	cpPath := filepath.Join(dir, "cp.json")
	seedStore(t, dsn, 5)
	cp, _ := checkpointAtHead(t, dsn)
	writeCheckpoint(t, cpPath, cp)

	// seedStore stamps event k (0-indexed) at base + (k+1) hours; an
	// exclusive --until of base+4h selects the first 3 events, whose head
	// is event 2's hash — not the attested chain head (event 4's).
	var code int
	stderr := captureStderr(t, func() {
		code = Run([]string{"--dsn", dsn, "--until", "1700014400", "--anchor", cpPath, "--out", out})
	})
	if code != 1 {
		t.Fatalf("mid-chain-window anchored export exit=%d, want 1", code)
	}
	if !strings.Contains(stderr, cp.Checkpoint.HeadHash) {
		t.Errorf("stderr must name the attested head:\n%s", stderr)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("no bundle file may be written, stat err=%v", err)
	}
}

// TestRun_AnchorMisuseExitsTwo (AC-13 / F12) pins that --anchor is a
// modifier, not a mode: alone it hits the existing required-mode exit-2
// branch, and paired with both --dsn and --verify it hits the existing
// mutual-exclusion exit-2 branch — both with the usage banner.
func TestRun_AnchorMisuseExitsTwo(t *testing.T) {
	cpPath := filepath.Join(t.TempDir(), "cp.json")
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"alone", []string{"--anchor", cpPath}, "required"},
		{"both-modes", []string{"--anchor", cpPath, "--dsn", "x.db", "--verify", "y.json"}, "mutually exclusive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var code int
			stderr := captureStderr(t, func() { code = Run(tc.args) })
			if code != 2 {
				t.Fatalf("exit=%d, want 2", code)
			}
			if !strings.Contains(stderr, tc.want) || !strings.Contains(stderr, progName) {
				t.Errorf("stderr missing misuse diagnostic + banner:\n%s", stderr)
			}
		})
	}
}

// TestRunVerify_AnchorNullTreatedAsAbsent (AC-14 / F13) pins the stripping
// equivalence: "anchor": null and a deleted anchor key both unmarshal to
// nil and behave exactly like a legacy unanchored bundle — exit 0, no
// anchor_head= on the OK line, no embedded warning (the flag is the only
// detector of an anchored-evidence downgrade).
func TestRunVerify_AnchorNullTreatedAsAbsent(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	seedStore(t, dsn, 3)

	for _, tc := range []struct {
		name    string
		rewrite func(t *testing.T, raw []byte) []byte
	}{
		{"null", func(t *testing.T, raw []byte) []byte {
			t.Helper()
			var m map[string]json.RawMessage
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			m["anchor"] = json.RawMessage("null")
			out, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			return out
		}},
		{"key-deleted", func(_ *testing.T, raw []byte) []byte { return raw }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(dir, tc.name+".json")
			if code := captureQuiet(t, func() int { return Run([]string{"--dsn", dsn, "--out", out}) }); code != 0 {
				t.Fatalf("export exit=%d", code)
			}
			raw, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(out, tc.rewrite(t, raw), 0o600); err != nil {
				t.Fatal(err)
			}
			var code int
			stderr := captureStderr(t, func() { code, _ = runVerify(out, "") })
			if code != 0 {
				t.Fatalf("verify exit=%d, want 0", code)
			}
			if strings.Contains(stderr, "anchor_head=") || strings.Contains(stderr, "warning=") {
				t.Errorf("stripped-anchor bundle must verify as legacy, no anchor/warning fields:\n%s", stderr)
			}
		})
	}
}

// TestRunVerify_EmbeddedForgeryPassesWithoutFlag (AC-9 / F14) locks in the
// trust boundary: a self-consistent forged embedded anchor (fresh key,
// signature over the actual checkpoint bytes, matching head) verifies
// without a flag — exit 0 WITH the convenience warning — because there is
// no key registry; the genuine --anchor flag then rejects the bundle
// (conflicting anchors, byte-level CheckpointEqual).
func TestRunVerify_EmbeddedForgeryPassesWithoutFlag(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	out := filepath.Join(dir, "evidence.json")
	cpPath := filepath.Join(dir, "cp.json")
	seedStore(t, dsn, 5)
	cp, _ := checkpointAtHead(t, dsn)
	writeCheckpoint(t, cpPath, cp)
	if code := captureQuiet(t, func() int { return Run([]string{"--dsn", dsn, "--out", out}) }); code != 0 {
		t.Fatalf("export exit=%d", code)
	}

	// Self-consistent forgery: the forger signs the real checkpoint bytes
	// and embeds its own key, so VerifyCheckpointSignature passes — this is
	// the F14 primitive, and why the embedded copy is not enforcement.
	forger, err := audit.NewEd25519CheckpointSigner()
	if err != nil {
		t.Fatal(err)
	}
	forgedRaw, err := json.Marshal(cp.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	forgedSig, err := forger.Sign(forgedRaw)
	if err != nil {
		t.Fatal(err)
	}
	forged := &audit.SignedCheckpoint{Checkpoint: cp.Checkpoint, Signature: forgedSig, SignerKey: forger.PublicKey()}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	forgedJSON, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	m["anchor"] = forgedJSON
	rewritten, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, rewritten, 0o600); err != nil {
		t.Fatal(err)
	}

	var code int
	stderr := captureStderr(t, func() { code, _ = runVerify(out, "") })
	if code != 0 {
		t.Fatalf("forged embedded anchor without flag exit=%d, want 0 (F14 is accepted, warned)", code)
	}
	if !strings.Contains(stderr, "warning=embedded-anchor-not-enforcement-grade") {
		t.Errorf("forged embedded verify must carry the convenience warning:\n%s", stderr)
	}

	// With the genuine flag the forgery cannot be silently overridden: the
	// byte-differing anchors conflict (F6).
	var flagged int
	flaggedStderr := captureStderr(t, func() { flagged = Run([]string{"--verify", out, "--anchor", cpPath}) })
	if flagged != 1 {
		t.Fatalf("genuine flag vs forged embedded exit=%d, want 1", flagged)
	}
	if !strings.Contains(flaggedStderr, "conflicting anchors") {
		t.Errorf("stderr missing conflicting-anchors diagnostic:\n%s", flaggedStderr)
	}
}

func TestBuildQuery_BadSince(t *testing.T) {
	if _, err := buildQuery(options{since: "not-a-time"}); err == nil {
		t.Error("bad --since should error")
	}
	if _, err := buildQuery(options{until: "not-a-time"}); err == nil {
		t.Error("bad --until should error")
	}
}

func TestBuildQuery_MapsFilters(t *testing.T) {
	q, err := buildQuery(options{
		typ: "login", actorID: "u1", tenantID: "t1", limit: 7,
		since: "1700000000", until: "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("buildQuery: %v", err)
	}
	if q.Type != audit.EventType("login") || q.ActorID != "u1" || q.TenantID != "t1" || q.Limit != 7 {
		t.Errorf("filters not mapped: %+v", q)
	}
	if q.Since.IsZero() || q.Until.IsZero() {
		t.Errorf("time bounds not parsed: since=%v until=%v", q.Since, q.Until)
	}
}

func TestParseTime(t *testing.T) {
	if _, err := parseTime("2026-01-01T00:00:00Z"); err != nil {
		t.Errorf("RFC3339: %v", err)
	}
	if got, err := parseTime("1700000000"); err != nil || got.Unix() != 1700000000 {
		t.Errorf("unix seconds: got=%v err=%v", got, err)
	}
	if _, err := parseTime("garbage"); err == nil {
		t.Error("garbage should error")
	}
}

func TestUsage_PrintsBanner(t *testing.T) {
	out := captureStderr(t, usage)
	for _, want := range []string{progName, "--dsn"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage missing %q:\n%s", want, out)
		}
	}
}

// captureQuiet runs fn with BOTH stdout and stderr redirected to
// discard so a bundle dump / summary doesn't pollute test output, and
// returns fn's exit code.
func captureQuiet(t *testing.T, fn func() int) int {
	t.Helper()
	origOut, origErr := os.Stdout, os.Stderr
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = devnull, devnull
	defer func() {
		os.Stdout, os.Stderr = origOut, origErr
		_ = devnull.Close()
	}()
	return fn()
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() {
		var b strings.Builder
		buf := make([]byte, 1024)
		for {
			n, e := r.Read(buf)
			b.Write(buf[:n])
			if e != nil {
				break
			}
		}
		done <- b.String()
	}()
	fn()
	_ = w.Close()
	out := <-done
	os.Stdout = orig
	return strings.TrimSpace(out)
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	done := make(chan string)
	go func() {
		var b strings.Builder
		buf := make([]byte, 1024)
		for {
			n, e := r.Read(buf)
			b.Write(buf[:n])
			if e != nil {
				break
			}
		}
		done <- b.String()
	}()
	fn()
	_ = w.Close()
	out := <-done
	os.Stderr = orig
	return strings.TrimSpace(out)
}

// ---------------------------------------------------------------------------
// B4-5 governed-store evidence (A1/A2/A3/A4 at the CLI): the store is
// seeded through the REAL connector (sqlite audit sink + same-tx outbox
// appender), the relay drains it, and the audit-export CLI produces and
// verifies the evidence bundle against it.
// ---------------------------------------------------------------------------

// seedGovernedStore wires the real B4-5 connector on one temp sqlite
// file and records the given events through it: each login_failure also
// commits an outbox fact in the audit row's transaction. Returns the
// outbox store (for relay/durability assertions) and the file DSN.
func seedGovernedStore(t *testing.T, dsn string, events []*audit.Event) *auditoutbox.SQLiteOutboxStore {
	t.Helper()
	outbox, err := auditoutbox.NewSQLiteOutboxStore(dsn)
	if err != nil {
		t.Fatalf("governed outbox: %v", err)
	}
	t.Cleanup(func() { _ = outbox.Close() })
	sink, err := auditsqlite.New(dsn, auditsqlite.WithTxAppender(outbox))
	if err != nil {
		t.Fatalf("governed sink: %v", err)
	}
	defer func() { _ = sink.Close() }()
	rec := audit.New(sink, audit.WithHashChain())
	for _, e := range events {
		rec.Record(context.Background(), e)
	}
	return outbox
}

// captureClient collects every fact the relay publishes (in-harness
// governance sink).
type captureClient struct {
	mu  sync.Mutex
	got []*commerce.OutboxEvent
}

func (c *captureClient) Publish(_ context.Context, event *commerce.OutboxEvent) (auditgovernance.Receipt, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, event)
	return auditgovernance.Receipt{EventID: event.ID, TenantID: event.TenantID, Status: "accepted", AcceptedAt: time.Now().UTC()}, nil
}

func (c *captureClient) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.got)
}

// TestRun_GovernedStoreSeedExportVerify is the A1/A2/A4 CLI leg: facts
// committed in-tx with the audit rows survive before the relay, the
// relay delivers each exactly once, and the exported bundle is
// contiguous with head matching the store and carries tenant_id + roles
// on the token_issued record.
func TestRun_GovernedStoreSeedExportVerify(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "governed.db")
	base := time.Unix(1700000000, 0).UTC()
	events := []*audit.Event{
		{ID: "lf-1", Type: audit.EventLoginFailure, Outcome: audit.OutcomeFailure,
			Timestamp: base, TenantID: "tenant-a", ClientID: "c1", Reason: "invalid_credentials"},
		{ID: "lf-2", Type: audit.EventLoginFailure, Outcome: audit.OutcomeFailure,
			Timestamp: base.Add(time.Minute), TenantID: "tenant-b", ClientID: "c2", Reason: "bad_password"},
		{ID: "ti-1", Type: audit.EventTokenIssued, Outcome: audit.OutcomeSuccess,
			Timestamp: base.Add(2 * time.Minute), TenantID: "tenant-a", ClientID: "c1",
			TokenStrategy: "jwt", ActorID: "user-1",
			Metadata: map[string]string{core.KeyRoles: "admin,auditor"}},
	}
	outbox := seedGovernedStore(t, dsn, events)

	ctx := context.Background()
	// A1 durability before the relay: both facts are committed.
	pending, err := outbox.Pending(ctx)
	if err != nil || len(pending) != 2 {
		t.Fatalf("pending facts before relay: %v %d (want 2 — in-tx commit)", err, len(pending))
	}
	// A1 relay: exactly one delivery per fact, none on the second pass.
	capture := &captureClient{}
	relay, err := auditgovernance.NewRelay(outbox, capture, auditgovernance.RelayConfig{Owner: "cli-e2e"})
	if err != nil {
		t.Fatalf("relay: %v", err)
	}
	result, err := relay.RunOnce(ctx)
	if err != nil || result.Delivered != 2 {
		t.Fatalf("relay run: %v result=%+v", err, result)
	}
	if capture.count() != 2 {
		t.Fatalf("deliveries: %d, want 2", capture.count())
	}
	if _, err := relay.RunOnce(ctx); err != nil {
		t.Fatalf("second relay run: %v", err)
	}
	if capture.count() != 2 {
		t.Errorf("duplicate deliveries after second run: %d", capture.count())
	}

	// A2/A4 export + verify.
	out := filepath.Join(dir, "evidence.json")
	if code := captureQuiet(t, func() int { return Run([]string{"--dsn", dsn, "--out", out}) }); code != 0 {
		t.Fatalf("export exit=%d, want 0", code)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	var b libexport.ExportBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !b.Contiguous {
		t.Error("governed-store export must be contiguous=true")
	}
	sink, err := auditsqlite.OpenReadOnly(dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = sink.Close() }()
	last, err := sink.LastHash(ctx)
	if err != nil {
		t.Fatalf("last hash: %v", err)
	}
	if b.HeadHash != last {
		t.Errorf("bundle head %q != store LastHash %q", b.HeadHash, last)
	}
	if b.EventCount != 3 {
		t.Fatalf("EventCount=%d, want 3", b.EventCount)
	}
	// A4: the exported token_issued record carries tenant_id + roles.
	issued := b.Events[len(b.Events)-1]
	if issued.Type != audit.EventTokenIssued || issued.TenantID != "tenant-a" {
		t.Errorf("token_issued tenant: type=%s tenant=%q", issued.Type, issued.TenantID)
	}
	if issued.Metadata[core.KeyRoles] != "admin,auditor" {
		t.Errorf("token_issued roles: got %q", issued.Metadata[core.KeyRoles])
	}
	if code := captureQuiet(t, func() int { return Run([]string{"--verify", out}) }); code != 0 {
		t.Fatalf("verify exit=%d, want 0", code)
	}
}

// TestRun_GovernedStoreAnchorFreshAndStale is the A3 CLI leg: a fresh
// checkpoint binds the export at the store head; a stale checkpoint
// (attesting the pre-growth head) is rejected in both modes.
func TestRun_GovernedStoreAnchorFreshAndStale(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "anchored.db")
	base := time.Unix(1700000000, 0).UTC()
	seedGovernedStore(t, dsn, []*audit.Event{
		{ID: "a1", Type: audit.EventLoginFailure, Outcome: audit.OutcomeFailure,
			Timestamp: base, TenantID: "tenant-a"},
		{ID: "a2", Type: audit.EventLoginFailure, Outcome: audit.OutcomeFailure,
			Timestamp: base.Add(time.Minute), TenantID: "tenant-a"},
	})

	// Fresh: signed checkpoint of the CURRENT head.
	cp, _ := checkpointAtHead(t, dsn)
	cpPath := filepath.Join(dir, "fresh.json")
	writeCheckpoint(t, cpPath, cp)
	out := filepath.Join(dir, "fresh-bundle.json")
	if code := captureQuiet(t, func() int { return Run([]string{"--dsn", dsn, "--anchor", cpPath, "--out", out}) }); code != 0 {
		t.Fatalf("fresh anchored export exit=%d, want 0", code)
	}
	if code := captureQuiet(t, func() int { return Run([]string{"--verify", out, "--anchor", cpPath}) }); code != 0 {
		t.Fatalf("fresh anchored verify exit=%d, want 0", code)
	}

	// Stale: grow the chain past the attestation, then re-anchor.
	seedGovernedStore(t, dsn, []*audit.Event{
		{ID: "a3", Type: audit.EventLoginFailure, Outcome: audit.OutcomeFailure,
			Timestamp: base.Add(2 * time.Minute), TenantID: "tenant-a"},
	})
	staleOut := filepath.Join(dir, "stale-bundle.json")
	if code := captureQuiet(t, func() int { return Run([]string{"--dsn", dsn, "--anchor", cpPath, "--out", staleOut}) }); code != 1 {
		t.Fatalf("stale anchored export exit=%d, want 1 (head mismatch)", code)
	}
	if _, err := os.Stat(staleOut); !os.IsNotExist(err) {
		t.Error("mismatched anchor must not leave a bundle file behind")
	}
}
