package auditverify

// Checkpoint-anchored verification tests (design §7, AC-1..AC-13).
//
// Byte-stability rules: Recorder stamps wall-clock timestamps, so event
// heads/hashes are NOT byte-stable across runs. Full-line exact equality
// is used only where no hash or timestamp is interpolated (AC-6a stdout,
// AC-6b stderr, AC-9 stderr) or where the expected text is built from the
// fixture (AC-1/5b/7c). All other rows use stable substrings / prefixes.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
)

// ---------------------------------------------------------------------------
// Fixture helpers (local; no cross-package sharing with auditexport).

// signedCheckpoint builds a REAL signed checkpoint attesting head with the
// given signer — the same construction the notary performs.
func signedCheckpoint(t *testing.T, signer audit.CheckpointSigner, seq int64, head string) *audit.SignedCheckpoint {
	t.Helper()
	cp := audit.Checkpoint{Sequence: seq, Timestamp: time.Now().UTC(), HeadHash: head}
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

// writeCheckpoint marshals a signed checkpoint to path as JSON.
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

// writeEventsFile writes events (chain order) to a temp JSON file and
// returns its path.
func writeEventsFile(t *testing.T, events []*audit.Event) string {
	t.Helper()
	raw, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "events.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeKeyFile writes hex-encoded keys (whitespace-separated) to a temp
// file and returns its path.
func writeKeyFile(t *testing.T, keys ...[]byte) string {
	t.Helper()
	var fields []string
	for _, k := range keys {
		fields = append(fields, hex.EncodeToString(k))
	}
	path := filepath.Join(t.TempDir(), "notary.pub.hex")
	if err := os.WriteFile(path, []byte(strings.Join(fields, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// forgedChain records an independent, internally consistent chain with
// distinct IDs and reasons — a whole-chain replacement whose head cannot
// equal an honest checkpoint's attestation.
func forgedChain(t *testing.T, n int) []*audit.Event {
	t.Helper()
	sink := audit.NewMemorySink(0)
	r := audit.New(sink, audit.WithHashChain())
	for i := range n {
		r.Record(context.Background(), &audit.Event{
			ID:      fmt.Sprintf("forged-%d", i),
			Type:    audit.EventLogin,
			Outcome: audit.OutcomeSuccess,
			Reason:  "forged",
		})
	}
	got, _ := sink.Query(context.Background(), audit.Query{Limit: n})
	for i, j := 0, len(got)-1; i < j; i, j = i+1, j-1 {
		got[i], got[j] = got[j], got[i]
	}
	return got
}

// urlServer serves newest-first pages of events like /api/v1/audit/events.
func urlServer(t *testing.T, events []*audit.Event) *httptest.Server {
	t.Helper()
	newestFirst := make([]*audit.Event, len(events))
	for i, e := range events {
		newestFirst[len(events)-1-i] = e
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/audit/events" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		off, _ := atoi(r.URL.Query().Get("offset"))
		lim, _ := atoi(r.URL.Query().Get("limit"))
		end := min(off+lim, len(newestFirst))
		_ = json.NewEncoder(w).Encode(map[string]any{"events": newestFirst[off:end]})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// runVerify invokes Run capturing stdout+stderr, returning code, stdout,
// and trimmed stderr.
func runVerify(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var code int
	var out, errOut string
	out = captureStdout(t, func() {
		errOut = captureStderr(t, func() {
			code = Run(args)
		})
	})
	return code, out, strings.TrimSpace(errOut)
}

// ---------------------------------------------------------------------------
// AC-1: anchored clean chain passes (file source, F11).

func TestRun_Checkpoint_HappyFile(t *testing.T) {
	events := chainedEvents(t, 3)
	signer, err := audit.NewEd25519CheckpointSigner()
	if err != nil {
		t.Fatal(err)
	}
	head := events[len(events)-1].Hash
	cp := signedCheckpoint(t, signer, 7, head)
	cpPath := filepath.Join(t.TempDir(), "cp.json")
	writeCheckpoint(t, cpPath, cp)

	code, out, _ := runVerify(t, "--from-file", writeEventsFile(t, events), "--checkpoint", cpPath)
	if code != 0 {
		t.Fatalf("exit = %d; want 0", code)
	}
	want := fmt.Sprintf("chain verified: 3 event(s), head=%s, checkpoint seq=7", head)
	if out != want {
		t.Errorf("stdout:\n got %q\nwant %q", out, want)
	}
}

// ---------------------------------------------------------------------------
// AC-2: tampered event detected (F7).

func TestRun_Checkpoint_TamperedEvent(t *testing.T) {
	events := chainedEvents(t, 3)
	signer, _ := audit.NewEd25519CheckpointSigner()
	cp := signedCheckpoint(t, signer, 7, events[len(events)-1].Hash)
	cpPath := filepath.Join(t.TempDir(), "cp.json")
	writeCheckpoint(t, cpPath, cp)

	events[1].Reason = "tampered"
	code, _, errOut := runVerify(t, "--from-file", writeEventsFile(t, events), "--checkpoint", cpPath)
	if code != 1 {
		t.Fatalf("exit = %d; want 1", code)
	}
	// VerifyChain errors propagate through VerifyChainAgainstCheckpoint
	// unwrapped: no "audit notary:" segment on this line. The AC-10
	// posture notice (no --notary-key) occupies the preceding stderr
	// line, so the lock targets the final line.
	lines := strings.Split(errOut, "\n")
	last := lines[len(lines)-1]
	if !strings.HasPrefix(last, "chain BROKEN: audit: hash mismatch") {
		t.Errorf("stderr:\n got %q\nwant final line prefix %q", errOut, "chain BROKEN: audit: hash mismatch")
	}
}

// ---------------------------------------------------------------------------
// AC-3: whole-chain replacement detected (file source, F8).

func TestRun_Checkpoint_WholeChainReplacement(t *testing.T) {
	honest := chainedEvents(t, 3)
	signer, _ := audit.NewEd25519CheckpointSigner()
	cp := signedCheckpoint(t, signer, 7, honest[len(honest)-1].Hash)
	cpPath := filepath.Join(t.TempDir(), "cp.json")
	writeCheckpoint(t, cpPath, cp)

	forged := forgedChain(t, 3)
	if forged[len(forged)-1].Hash == honest[len(honest)-1].Hash {
		t.Fatal("fixture collision: forged head equals honest head")
	}
	code, _, errOut := runVerify(t, "--from-file", writeEventsFile(t, forged), "--checkpoint", cpPath)
	if code != 1 {
		t.Fatalf("exit = %d; want 1", code)
	}
	if !strings.Contains(errOut, "does not match checkpoint attestation") {
		t.Errorf("stderr %q; want substring %q", errOut, "does not match checkpoint attestation")
	}
}

// ---------------------------------------------------------------------------
// AC-4: invalid checkpoint signature (F3) — signature bytes corrupted, NOT
// re-signed by a different key (a re-signed checkpoint with SignerKey
// updated verifies clean under embedded-key trust; that is the F6 forge,
// closed only by --notary-key, see AC-7b).

func TestRun_Checkpoint_BadSignature(t *testing.T) {
	events := chainedEvents(t, 3)
	signer, _ := audit.NewEd25519CheckpointSigner()
	cp := signedCheckpoint(t, signer, 7, events[len(events)-1].Hash)
	mut := *cp
	mut.Signature = append([]byte(nil), cp.Signature...)
	mut.Signature[0] ^= 0xff
	cpPath := filepath.Join(t.TempDir(), "cp.json")
	writeCheckpoint(t, cpPath, &mut)

	code, _, errOut := runVerify(t, "--from-file", writeEventsFile(t, events), "--checkpoint", cpPath)
	if code != 1 {
		t.Fatalf("exit = %d; want 1", code)
	}
	if !strings.Contains(errOut, "checkpoint signature invalid") {
		t.Errorf("stderr %q; want substring %q", errOut, "checkpoint signature invalid")
	}
}

// ---------------------------------------------------------------------------
// AC-12: checkpoint file unreadable (F1).

func TestRun_Checkpoint_UnreadableFile(t *testing.T) {
	events := chainedEvents(t, 3)
	missing := filepath.Join(t.TempDir(), "nope.json")
	code, _, errOut := runVerify(t, "--from-file", writeEventsFile(t, events), "--checkpoint", missing)
	if code != 1 {
		t.Fatalf("exit = %d; want 1", code)
	}
	if want := "read checkpoint " + missing + ":"; !strings.Contains(errOut, want) {
		t.Errorf("stderr %q; want substring %q", errOut, want)
	}
}

// ---------------------------------------------------------------------------
// AC-13: checkpoint not SignedCheckpoint JSON (F2) — truncated bytes so
// json.Unmarshal fails (a structurally-valid wrong object falls through to
// the fail-closed signature check instead; both exit 1).

func TestRun_Checkpoint_BadJSON(t *testing.T) {
	events := chainedEvents(t, 3)
	cpPath := filepath.Join(t.TempDir(), "cp.json")
	if err := os.WriteFile(cpPath, []byte(`{"checkpoint":`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runVerify(t, "--from-file", writeEventsFile(t, events), "--checkpoint", cpPath)
	if code != 1 {
		t.Fatalf("exit = %d; want 1", code)
	}
	if want := "parse checkpoint " + cpPath + ":"; !strings.Contains(errOut, want) {
		t.Errorf("stderr %q; want substring %q", errOut, want)
	}
}

// ---------------------------------------------------------------------------
// AC-5a/5b: compromised vs honest server via live URL (F8/F11).

func TestRun_Checkpoint_URLForgedChain(t *testing.T) {
	honest := chainedEvents(t, 3)
	signer, _ := audit.NewEd25519CheckpointSigner()
	cp := signedCheckpoint(t, signer, 7, honest[len(honest)-1].Hash)
	cpPath := filepath.Join(t.TempDir(), "cp.json")
	writeCheckpoint(t, cpPath, cp)

	forged := forgedChain(t, 3)
	srv := urlServer(t, forged)
	code, _, errOut := runVerify(t, "--from-url", srv.URL, "--bearer", "t", "--checkpoint", cpPath)
	if code != 1 {
		t.Fatalf("exit = %d; want 1", code)
	}
	if !strings.Contains(errOut, "does not match checkpoint attestation") {
		t.Errorf("stderr %q; want substring %q", errOut, "does not match checkpoint attestation")
	}
}

func TestRun_Checkpoint_URLHonestChain(t *testing.T) {
	events := chainedEvents(t, 3)
	signer, _ := audit.NewEd25519CheckpointSigner()
	head := events[len(events)-1].Hash
	cp := signedCheckpoint(t, signer, 7, head)
	cpPath := filepath.Join(t.TempDir(), "cp.json")
	writeCheckpoint(t, cpPath, cp)

	srv := urlServer(t, events)
	code, out, _ := runVerify(t, "--from-url", srv.URL, "--bearer", "t", "--checkpoint", cpPath)
	if code != 0 {
		t.Fatalf("exit = %d; want 0", code)
	}
	want := fmt.Sprintf("chain verified: 3 event(s), head=%s, checkpoint seq=7", head)
	if out != want {
		t.Errorf("stdout:\n got %q\nwant %q", out, want)
	}
}

// ---------------------------------------------------------------------------
// AC-6a: empty events + genesis attestation (F10). Also the ordering
// canary: the anchored branch must precede the legacy empty early return
// (which would silently fail open as "no events to verify").

func TestRun_Checkpoint_EmptyChainGenesis(t *testing.T) {
	signer, _ := audit.NewEd25519CheckpointSigner()
	cp := signedCheckpoint(t, signer, 1, audit.GenesisHash)
	cpPath := filepath.Join(t.TempDir(), "cp.json")
	writeCheckpoint(t, cpPath, cp)

	emptyPath := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(emptyPath, []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runVerify(t, "--from-file", emptyPath, "--checkpoint", cpPath)
	if code != 0 {
		t.Fatalf("exit = %d; want 0", code)
	}
	want := "chain verified: 0 event(s), head=, checkpoint seq=1"
	if out != want {
		t.Errorf("stdout:\n got %q\nwant %q", out, want)
	}
}

// ---------------------------------------------------------------------------
// AC-6b: empty events + non-genesis attestation (F9) — the only fully
// deterministic negative line: exact lock on wrapper prefix AND chainer
// propagation together.

func TestRun_Checkpoint_EmptyChainNonGenesis(t *testing.T) {
	events := chainedEvents(t, 3)
	signer, _ := audit.NewEd25519CheckpointSigner()
	head := events[len(events)-1].Hash
	cp := signedCheckpoint(t, signer, 7, head)
	cpPath := filepath.Join(t.TempDir(), "cp.json")
	writeCheckpoint(t, cpPath, cp)

	emptyPath := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(emptyPath, []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runVerify(t, "--from-file", emptyPath, "--checkpoint", cpPath)
	if code != 1 {
		t.Fatalf("exit = %d; want 1", code)
	}
	// The AC-10 posture notice (no --notary-key) precedes the failure
	// line; the exact lock targets the final line so it pins the wrapper
	// prefix AND the chainer propagation together.
	lines := strings.Split(errOut, "\n")
	last := lines[len(lines)-1]
	want := fmt.Sprintf(`chain BROKEN: audit notary: empty chain head "", checkpoint attests %q`, head)
	if last != want {
		t.Errorf("stderr:\n got %q\nwant final line %q", errOut, want)
	}
}

// ---------------------------------------------------------------------------
// AC-7a: --notary-key without --checkpoint (F4) — exit 2 returned from Run.

func TestRun_NotaryKeyWithoutCheckpoint(t *testing.T) {
	key := writeKeyFile(t, make([]byte, 32))
	code, _, _ := runVerify(t, "--notary-key", key)
	if code != 2 {
		t.Fatalf("exit = %d; want 2 (CLI misuse)", code)
	}
}

// ---------------------------------------------------------------------------
// AC-7b: pinned key rejects the self-signed forge (F6).

func TestRun_Checkpoint_PinnedRejectsForge(t *testing.T) {
	honestSigner, _ := audit.NewEd25519CheckpointSigner()
	attacker, _ := audit.NewEd25519CheckpointSigner()
	// Attacker self-signed checkpoint: valid under its OWN embedded key.
	forgedEvents := forgedChain(t, 3)
	forged := signedCheckpoint(t, attacker, 99, forgedEvents[len(forgedEvents)-1].Hash)
	cpPath := filepath.Join(t.TempDir(), "cp.json")
	writeCheckpoint(t, cpPath, forged)

	code, _, errOut := runVerify(t,
		"--from-file", writeEventsFile(t, forgedEvents),
		"--checkpoint", cpPath,
		"--notary-key", writeKeyFile(t, honestSigner.PublicKey()))
	if code != 1 {
		t.Fatalf("exit = %d; want 1", code)
	}
	if !strings.Contains(errOut, "does not match pinned key") {
		t.Errorf("stderr %q; want substring %q", errOut, "does not match pinned key")
	}
}

// ---------------------------------------------------------------------------
// AC-7c: pinned key accepts the honest checkpoint (F11, pinned).

func TestRun_Checkpoint_PinnedAcceptsHonest(t *testing.T) {
	events := chainedEvents(t, 3)
	signer, _ := audit.NewEd25519CheckpointSigner()
	head := events[len(events)-1].Hash
	cp := signedCheckpoint(t, signer, 7, head)
	cpPath := filepath.Join(t.TempDir(), "cp.json")
	writeCheckpoint(t, cpPath, cp)

	code, out, _ := runVerify(t,
		"--from-file", writeEventsFile(t, events),
		"--checkpoint", cpPath,
		"--notary-key", writeKeyFile(t, signer.PublicKey()))
	if code != 0 {
		t.Fatalf("exit = %d; want 0", code)
	}
	want := fmt.Sprintf("chain verified: 3 event(s), head=%s, checkpoint seq=7", head)
	if out != want {
		t.Errorf("stdout:\n got %q\nwant %q", out, want)
	}
}

// ---------------------------------------------------------------------------
// AC-7d: unreadable / non-hex / wrong-length key file (F5).

func TestRun_Checkpoint_BadKeyFile(t *testing.T) {
	events := chainedEvents(t, 3)
	signer, _ := audit.NewEd25519CheckpointSigner()
	cp := signedCheckpoint(t, signer, 7, events[len(events)-1].Hash)
	cpPath := filepath.Join(t.TempDir(), "cp.json")
	writeCheckpoint(t, cpPath, cp)
	eventsPath := writeEventsFile(t, events)

	// Missing key file.
	missing := filepath.Join(t.TempDir(), "missing.pub.hex")
	code, _, errOut := runVerify(t, "--from-file", eventsPath, "--checkpoint", cpPath, "--notary-key", missing)
	if code != 1 {
		t.Fatalf("missing key file: exit = %d; want 1", code)
	}
	if !strings.Contains(errOut, "read notary key "+missing) {
		t.Errorf("missing key file stderr %q; want read error", errOut)
	}

	// Non-hex field.
	badHex := filepath.Join(t.TempDir(), "badhex.pub.hex")
	if err := os.WriteFile(badHex, []byte("zzzz-not-hex"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut = runVerify(t, "--from-file", eventsPath, "--checkpoint", cpPath, "--notary-key", badHex)
	if code != 1 {
		t.Fatalf("non-hex key: exit = %d; want 1", code)
	}
	if !strings.Contains(errOut, "invalid hex") {
		t.Errorf("non-hex key stderr %q; want invalid-hex error", errOut)
	}

	// Wrong-length key (31 bytes decodes fine but is not Ed25519 size).
	short := writeKeyFile(t, make([]byte, 31))
	code, _, errOut = runVerify(t, "--from-file", eventsPath, "--checkpoint", cpPath, "--notary-key", short)
	if code != 1 {
		t.Fatalf("short key: exit = %d; want 1", code)
	}
	if !strings.Contains(errOut, "want 32") {
		t.Errorf("short key stderr %q; want length error", errOut)
	}
}

// ---------------------------------------------------------------------------
// AC-8: regression lock — NEW unanchored Run-level golden tests (the
// claimed locks did not exist: TestRun_VerifyHappyPath is a contains-check,
// TestVerifyDetectsTamper never calls Run). Scope: clean/tamper/empty only;
// legacy usageErr/errorf paths still os.Exit in-process.

func TestRun_Golden_HappyUnanchored(t *testing.T) {
	events := chainedEvents(t, 3)
	code, out, errOut := runVerify(t, "--from-file", writeEventsFile(t, events))
	if code != 0 {
		t.Fatalf("exit = %d; want 0", code)
	}
	want := fmt.Sprintf("chain verified: 3 event(s), head=%s", events[len(events)-1].Hash)
	if out != want {
		t.Errorf("stdout:\n got %q\nwant %q", out, want)
	}
	if errOut != "" {
		t.Errorf("stderr = %q; want empty", errOut)
	}
}

func TestRun_Golden_TamperedUnanchored(t *testing.T) {
	events := chainedEvents(t, 3)
	events[1].Reason = "tampered"
	code, _, errOut := runVerify(t, "--from-file", writeEventsFile(t, events))
	if code != 1 {
		t.Fatalf("exit = %d; want 1", code)
	}
	if !strings.HasPrefix(errOut, "chain BROKEN: ") || !strings.Contains(errOut, "audit: hash mismatch") {
		t.Errorf("stderr %q; want chain BROKEN with audit: hash mismatch", errOut)
	}
}

func TestRun_Golden_EmptyUnanchored(t *testing.T) {
	emptyPath := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(emptyPath, []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runVerify(t, "--from-file", emptyPath)
	if code != 0 {
		t.Fatalf("exit = %d; want 0", code)
	}
	if out != "no events to verify" {
		t.Errorf("stdout = %q; want %q", out, "no events to verify")
	}
	if errOut != "" {
		t.Errorf("stderr = %q; want empty", errOut)
	}
}

// ---------------------------------------------------------------------------
// AC-9: --limit truncation under --checkpoint is a mandatory fail-fast
// (F12), before any verification, exact stderr line.

func TestRun_Checkpoint_LimitTruncationFile(t *testing.T) {
	events := chainedEvents(t, 5)
	signer, _ := audit.NewEd25519CheckpointSigner()
	cp := signedCheckpoint(t, signer, 7, events[len(events)-1].Hash)
	cpPath := filepath.Join(t.TempDir(), "cp.json")
	writeCheckpoint(t, cpPath, cp)

	code, _, errOut := runVerify(t, "--from-file", writeEventsFile(t, events), "--checkpoint", cpPath, "--limit", "4")
	if code != 1 {
		t.Fatalf("exit = %d; want 1", code)
	}
	want := "event list truncated by --limit 4 before the attested head; rerun with --limit 0"
	if errOut != want {
		t.Errorf("stderr:\n got %q\nwant %q", errOut, want)
	}
}

func TestRun_Checkpoint_LimitTruncationURL(t *testing.T) {
	events := chainedEvents(t, 6)
	signer, _ := audit.NewEd25519CheckpointSigner()
	cp := signedCheckpoint(t, signer, 7, events[len(events)-1].Hash)
	cpPath := filepath.Join(t.TempDir(), "cp.json")
	writeCheckpoint(t, cpPath, cp)

	srv := urlServer(t, events)
	code, _, errOut := runVerify(t, "--from-url", srv.URL, "--bearer", "t", "--checkpoint", cpPath, "--limit", "5")
	if code != 1 {
		t.Fatalf("exit = %d; want 1", code)
	}
	want := "event list truncated by --limit 5 before the attested head; rerun with --limit 0"
	if errOut != want {
		t.Errorf("stderr:\n got %q\nwant %q", errOut, want)
	}
}

// Probe-path unit check: exactly `limit` events collected plus a non-empty
// probe page means truncation (server has one more event past the cap).
func TestReadFromURL_ProbeDetectsTruncation(t *testing.T) {
	events := chainedEvents(t, 6)
	srv := urlServer(t, events)
	// pageSize 5, limit 5: first page fills the cap exactly; the probe at
	// offset 5 must find the sixth event.
	got, truncated, err := readFromURL(srv.URL, "t", 5, 5, time.Second)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 5 {
		t.Errorf("got %d events; want 5", len(got))
	}
	if !truncated {
		t.Error("truncated = false; want true (probe found more events)")
	}
}

// ---------------------------------------------------------------------------
// AC-10: Phase-A posture notice — --checkpoint without --notary-key prints
// the embedded-key-trust notice on stderr, exit unchanged.

func TestRun_Checkpoint_PhaseANotice(t *testing.T) {
	events := chainedEvents(t, 3)
	signer, _ := audit.NewEd25519CheckpointSigner()
	cp := signedCheckpoint(t, signer, 7, events[len(events)-1].Hash)
	cpPath := filepath.Join(t.TempDir(), "cp.json")
	writeCheckpoint(t, cpPath, cp)

	code, _, errOut := runVerify(t, "--from-file", writeEventsFile(t, events), "--checkpoint", cpPath)
	if code != 0 {
		t.Fatalf("exit = %d; want 0", code)
	}
	if !strings.Contains(errOut, "no --notary-key") || !strings.Contains(errOut, "forgeable") {
		t.Errorf("stderr %q; want embedded-key-trust notice", errOut)
	}
}

// ---------------------------------------------------------------------------
// AC-11: pin rotation — match-any key set (old+new keys pass; removing the
// new key rejects).

func TestRun_Checkpoint_PinRotation(t *testing.T) {
	events := chainedEvents(t, 3)
	oldSigner, _ := audit.NewEd25519CheckpointSigner()
	newSigner, _ := audit.NewEd25519CheckpointSigner()
	head := events[len(events)-1].Hash
	cp := signedCheckpoint(t, newSigner, 8, head)
	cpPath := filepath.Join(t.TempDir(), "cp.json")
	writeCheckpoint(t, cpPath, cp)
	eventsPath := writeEventsFile(t, events)

	// Rotation window: old + new both pinned; new key signs.
	both := writeKeyFile(t, oldSigner.PublicKey(), newSigner.PublicKey())
	code, out, _ := runVerify(t, "--from-file", eventsPath, "--checkpoint", cpPath, "--notary-key", both)
	if code != 0 {
		t.Fatalf("both keys: exit = %d; want 0", code)
	}
	want := fmt.Sprintf("chain verified: 3 event(s), head=%s, checkpoint seq=8", head)
	if out != want {
		t.Errorf("stdout:\n got %q\nwant %q", out, want)
	}

	// After retirement: only the old key remains; new-key checkpoint rejected.
	onlyOld := writeKeyFile(t, oldSigner.PublicKey())
	code, _, errOut := runVerify(t, "--from-file", eventsPath, "--checkpoint", cpPath, "--notary-key", onlyOld)
	if code != 1 {
		t.Fatalf("old key only: exit = %d; want 1", code)
	}
	if !strings.Contains(errOut, "does not match pinned key") {
		t.Errorf("old key only stderr %q; want pin mismatch", errOut)
	}
}
