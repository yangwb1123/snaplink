// Package auditverify reads audit events (from a JSON file, the live
// /api/v1/audit/events API, or a durable sqlite/postgres audit store via
// --dsn) and runs them through audit.VerifyChain to confirm the
// tamper-evident hash chain is intact.
//
// Usage:
//
//	sso-ctl audit-verify --from-file events.json
//	sso-ctl audit-verify --from-url https://sso.example.com --bearer $ADMIN_TOKEN
//	sso-ctl audit-verify --dsn <sqlite-dsn|postgres-dsn>
//	sso-ctl audit-verify --from-file events.json --checkpoint cp.json [--notary-key notary.pub.hex]
//	sso-ctl audit-verify --from-file window.json --anchor-hash <boundary-prev-hash>
//
// All sources are mutually exclusive. URL mode pages through
// /api/v1/audit/events newest-first and reverses the buffer before
// verifying; DSN mode pages the durable store through the shared
// auditstore reader — the chain runs oldest-first per audit.VerifyChain
// semantics. The query API caps each page at
// audit.MaxQueryLimit (1000); --page-size lets operators tune. --dsn
// opens the store read-only (never migrates; a schema-version mismatch
// is reported, exit 1) and --timeout-sec is not applicable to DSN mode
// (no HTTP client is built).
//
// --checkpoint anchors verification to a signed notary attestation of
// the chain head: instead of proving only internal consistency, the
// replayed head must equal the attested head (audit.VerifyChainAgainstCheckpoint).
// --notary-key pins the checkpoint signer out-of-band (one or more
// hex-encoded Ed25519 public keys, whitespace-separated) so a replaced
// checkpoint file cannot simply be re-signed by an attacker.
//
// --anchor-hash anchors verification to the segment START: the boundary
// PrevHash the oldest exported event carried at export time (an
// auditexport bundle's boundary_prev_hash, the event before the window in
// a full export, or a relayed batch's first event — NOT a checkpoint
// file). --checkpoint proves the chain END; --anchor-hash proves the
// segment START; the two are mutually exclusive (R5).
//
// Honest head reporting — a --limit-truncated run verifies the PREFIX and
// says so (exit 1), never asserting the prefix head is the chain tip:
// segment verified (0), prefix verified ... not the full chain (1),
// chain BROKEN (1), empty segment (1), CLI misuse (2).
// Exit code: 0 on a clean chain, 1 on a break / error, 2 on CLI misuse.
package auditverify

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
)

const progName = "sso-ctl audit-verify"

// usage prints the standard "<prog> — <desc> / Usage / Flags" banner.
// Wired as the FlagSet's Usage so -h and parse errors render it. The
// flag defaults come from the FlagSet built in Run; usageFlags holds
// that set so the standalone banner (also exercised directly in tests)
// stays self-contained.
var usageFlags *flag.FlagSet

func usage() {
	fmt.Fprint(os.Stderr, progName+` — verify the tamper-evident audit hash chain offline.

Usage:
  `+progName+` --from-file events.json
  `+progName+` --from-url https://sso.example.com --bearer $ADMIN_TOKEN
  `+progName+` --dsn <sqlite-dsn|postgres-dsn>

Flags:
`)
	if usageFlags != nil {
		usageFlags.PrintDefaults()
	}
}

// verifyOptions carries the parsed flag values between Run and its
// helpers (flag pointers only live inside parseFlags' FlagSet).
type verifyOptions struct {
	fromFile      string
	fromURL       string
	dsn           string
	bearer        string
	limit         int
	pageSize      int
	timeout       time.Duration
	checkpoint    string
	notaryKey     string
	anchorHash    string
	anchorHashSet bool
}

// parseFlags builds the local FlagSet (wired as usageFlags so the
// standalone usage banner renders the defaults) and returns the parsed
// options.
func parseFlags(args []string) verifyOptions {
	fs := flag.NewFlagSet("sso-ctl audit-verify", flag.ExitOnError)
	usageFlags = fs
	fs.Usage = usage
	fromFile := fs.String("from-file", "", "path to JSON array of audit events (mutually exclusive with --from-url and --dsn)")
	fromURL := fs.String("from-url", "", "base URL of the SSO server (mutually exclusive with --from-file and --dsn)")
	dsn := fs.String("dsn", "", "audit store DSN to read from (sqlite file DSN or postgres://|postgresql:// connection string; opened read-only, never migrated; mutually exclusive with --from-file and --from-url)")
	bearer := fs.String("bearer", "", "admin bearer token for the /api/v1/audit/events API (required with --from-url; not applicable with --dsn)")
	limit := fs.Int("limit", 10_000, "max events to load (0 = unlimited; prefer 0 for anchored runs)")
	pageSize := fs.Int("page-size", 500, "URL-mode pagination batch size (caps at audit.MaxQueryLimit=1000)")
	timeoutSec := fs.Int("timeout-sec", 30, "URL-mode HTTP timeout in seconds")
	checkpoint := fs.String("checkpoint", "", "path to a signed notary checkpoint (JSON); signature enforced at load")
	notaryKey := fs.String("notary-key", "", "path to hex-encoded Ed25519 public key(s) pinning the checkpoint signer (one or more, whitespace-separated; requires --checkpoint)")
	anchorHash := fs.String("anchor-hash", "", "hex PrevHash of the segment's first event — the boundary anchor (an auditexport bundle's boundary_prev_hash, the event before the window in a full export, or a relayed batch's first event); NOT a checkpoint file — verifies the segment START instead of genesis")
	_ = fs.Parse(args)
	// An explicit --anchor-hash "" is misuse (R5): the empty anchor is
	// GenesisHash, expressed by OMITTING the flag. flag.Visit tells an
	// explicitly-set empty value apart from an absent flag.
	anchorHashSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "anchor-hash" {
			anchorHashSet = true
		}
	})
	return verifyOptions{
		fromFile:      *fromFile,
		fromURL:       *fromURL,
		dsn:           *dsn,
		bearer:        *bearer,
		limit:         *limit,
		pageSize:      *pageSize,
		timeout:       time.Duration(*timeoutSec) * time.Second,
		checkpoint:    *checkpoint,
		notaryKey:     *notaryKey,
		anchorHash:    *anchorHash,
		anchorHashSet: anchorHashSet,
	}
}

// loadEvents reads events from the flag-selected source and reports
// whether the --limit cap truncated the chain (checkpoint-anchored runs
// fail fast on that; --anchor-hash and legacy runs report the truncation
// honestly instead). URL mode requires a bearer token (legacy misuse path).
func loadEvents(o verifyOptions) ([]*audit.Event, bool, error) {
	if o.fromFile != "" {
		return readFromFile(o.fromFile, o.limit)
	}
	if o.dsn != "" {
		return readFromStore(o.dsn, o.limit, o.pageSize)
	}
	if o.bearer == "" {
		usageErr("--bearer is required with --from-url")
	}
	return readFromURL(o.fromURL, o.bearer, o.limit, o.pageSize, o.timeout)
}

// verifyAnchored is the --checkpoint branch of Run: truncation fail-fast,
// the Phase-A posture notice, then VerifyChainAgainstCheckpoint (which
// re-verifies the embedded-key signature, replays the chain, applies the
// empty-set rule, and asserts head equality). Returns the exit code.
func verifyAnchored(events []*audit.Event, cp *audit.SignedCheckpoint, notaryKeyPath string, limit int, truncated bool) int {
	// A --limit-truncated list verifies against the wrong head and is
	// indistinguishable from a genuine compromise alarm (--limit defaults
	// to 10000, so truncation is the default state on long chains).
	// Fail-fast BEFORE any verification output.
	if truncated {
		fmt.Fprintf(os.Stderr, "event list truncated by --limit %d before the attested head; rerun with --limit 0\n", limit)
		return 1
	}
	if notaryKeyPath == "" {
		// Phase-A posture, self-announcing: without a pin, a checkpoint
		// file an attacker can replace is forgeable (embedded-key trust).
		fmt.Fprintln(os.Stderr, "notice: no --notary-key: a checkpoint file an attacker can replace is forgeable (embedded-key trust) — add --notary-key to pin the signer")
	}
	if err := audit.VerifyChainAgainstCheckpoint(events, cp); err != nil {
		fmt.Fprintf(os.Stderr, "chain BROKEN: %v\n", err)
		return 1
	}
	// GenesisHash ("") is the only head an empty chain can attest;
	// guarding the slice keeps the anchored empty-chain path panic-free.
	head := audit.GenesisHash
	if len(events) > 0 {
		head = events[len(events)-1].Hash
	}
	fmt.Printf("chain verified: %d event(s), head=%s, checkpoint seq=%d\n",
		len(events), head, cp.Checkpoint.Sequence)
	return 0
}

// checkMisuse validates the CLI-flag rules and returns a nonzero exit
// code for misuse, or 0. --notary-key without --checkpoint is checked
// first so the misuse code 2 is RETURNED (in-process-testable; binary
// behavior is unchanged via the os.Exit(run(args)) dispatcher), while
// the legacy source-flag rules keep their os.Exit behavior (R4).
func checkMisuse(o verifyOptions) int {
	if o.notaryKey != "" && o.checkpoint == "" {
		fmt.Fprintf(os.Stderr, progName+": --notary-key requires --checkpoint\n")
		usage()
		return 2
	}
	if o.anchorHashSet && o.anchorHash == "" {
		fmt.Fprintf(os.Stderr, progName+": --anchor-hash requires a non-empty value\n")
		usage()
		return 2
	}
	if o.anchorHashSet && o.checkpoint != "" {
		fmt.Fprintf(os.Stderr, progName+": --anchor-hash and --checkpoint are mutually exclusive\n")
		usage()
		return 2
	}
	if code := checkDSNMisuse(o); code != 0 {
		return code
	}
	if o.fromFile == "" && o.fromURL == "" && o.dsn == "" {
		usageErr("one of --from-file, --from-url, or --dsn is required")
	}
	if o.fromFile != "" && o.fromURL != "" {
		usageErr("--from-file and --from-url are mutually exclusive")
	}
	return 0
}

// checkDSNMisuse validates the --dsn source rules: a DSN is exclusive
// with the other sources and never combines with --bearer (DSN mode reads
// the store directly, no HTTP client). Returns 2 + the banner for misuse;
// 0 otherwise. Split out of checkMisuse to hold the function under the
// complexity budget.
func checkDSNMisuse(o verifyOptions) int {
	if o.dsn != "" && (o.fromFile != "" || o.fromURL != "") {
		fmt.Fprintf(os.Stderr, progName+": --dsn is mutually exclusive with --from-file and --from-url\n")
		usage()
		return 2
	}
	if o.dsn != "" && o.bearer != "" {
		fmt.Fprintf(os.Stderr, progName+": --bearer is not applicable with --dsn (DSN mode reads the store directly)\n")
		usage()
		return 2
	}
	return 0
}

// loadCheckpointIfRequested loads the anchor when --checkpoint is set; a
// load failure prints the diagnostic and returns a nonzero exit code.
// The checkpoint loads BEFORE events: a bad anchor fails fast without
// touching the event source (mirrors auditexport ordering).
func loadCheckpointIfRequested(checkpointPath, notaryKeyPath string) (*audit.SignedCheckpoint, int) {
	if checkpointPath == "" {
		return nil, 0
	}
	cp, err := loadAnchor(checkpointPath, notaryKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, progName+": %v\n", err)
		return nil, 1
	}
	return cp, 0
}

// Run executes the audit-verify subcommand over args (the argument
// slice WITHOUT the leading program name). It returns the process exit
// code: 0 on a clean chain / empty input, 1 on a chain break or load
// error, 2 on CLI misuse. New failure paths (checkpoint load, pinning,
// truncation fail-fast, --notary-key misuse) print their diagnostic and
// RETURN the code so tests can exercise them in-process; legacy
// usageErr/errorf paths still exit the process directly (the binary
// behavior is identical either way because cmd/sso-ctl main() does
// os.Exit(run(args))).
func Run(args []string) int {
	o := parseFlags(args)
	if code := checkMisuse(o); code != 0 {
		return code
	}

	cp, code := loadCheckpointIfRequested(o.checkpoint, o.notaryKey)
	if code != 0 {
		return code
	}

	events, truncated, err := loadEvents(o)
	if err != nil {
		fmt.Fprintf(os.Stderr, progName+": load events: %v\n", err)
		return 1
	}
	if cp != nil {
		return verifyAnchored(events, cp, o.notaryKey, o.limit, truncated)
	}
	if o.anchorHashSet {
		return verifyAnchoredSegment(events, o.anchorHash, o.limit, truncated)
	}

	// Legacy unanchored tail — byte-identical when no checkpoint or
	// anchor-hash flag is present (R4), except the truncated row below:
	// a --limit-truncated prefix must never assert its head is the tip.
	if len(events) == 0 {
		fmt.Println("no events to verify")
		return 0
	}

	if err := audit.VerifyChain(events); err != nil {
		fmt.Fprintf(os.Stderr, "chain BROKEN: %v\n", err)
		return 1
	}
	if truncated {
		fmt.Printf("prefix verified: %d event(s) — truncated by --limit %d; head=%s is not the full chain\n",
			len(events), o.limit, events[len(events)-1].Hash)
		return 1
	}
	fmt.Printf("chain verified: %d event(s), head=%s\n", len(events), events[len(events)-1].Hash)
	return 0
}

// loadCheckpoint reads the SignedCheckpoint JSON exactly once and
// enforces the embedded-key signature at load (read-once, no TOCTOU;
// same pattern as auditexport.loadCheckpoint).
func loadCheckpoint(path string) (*audit.SignedCheckpoint, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read checkpoint %s: %w", path, err)
	}
	var cp audit.SignedCheckpoint
	if err := json.Unmarshal(raw, &cp); err != nil {
		return nil, fmt.Errorf("parse checkpoint %s: %w", path, err)
	}
	if err := audit.VerifyCheckpointSignature(&cp); err != nil {
		return nil, fmt.Errorf("checkpoint %s FAILED signature check: %w", path, err)
	}
	return &cp, nil
}

// readPinnedKeys reads one or more hex-encoded Ed25519 public keys (each
// 32 bytes -> 64 hex chars; whitespace-separated, trimmed) into a set.
// The set form exists for rotation: add the new key, rotate the notary,
// remove the old key — no verification gap.
func readPinnedKeys(path string) (map[string][]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read notary key %s: %w", path, err)
	}
	pinned := make(map[string][]byte)
	for _, field := range strings.Fields(string(raw)) {
		key, err := hex.DecodeString(field)
		if err != nil {
			return nil, fmt.Errorf("parse notary key %s: invalid hex %q", path, field)
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("parse notary key %s: %q is %d bytes; want %d", path, field, len(key), ed25519.PublicKeySize)
		}
		pinned[string(key)] = key
	}
	if len(pinned) == 0 {
		return nil, fmt.Errorf("parse notary key %s: no keys found", path)
	}
	return pinned, nil
}

// loadAnchor composes loadCheckpoint + optional pinning: when a pin file
// is given, cp.SignerKey must be a member of the pinned set. Membership
// is the load-bearing precondition: after it passes, VerifyCheckpointSignature
// (which verifies against SignerKey) verifies against a pinned key by
// construction. Do not "simplify" this into a SignerKey-only check (that
// reopens the self-signed-checkpoint forge) or into a single-key match
// (that makes rotation a fail-closed outage).
func loadAnchor(checkpointPath, notaryKeyPath string) (*audit.SignedCheckpoint, error) {
	cp, err := loadCheckpoint(checkpointPath)
	if err != nil {
		return nil, err
	}
	if notaryKeyPath == "" {
		return cp, nil
	}
	pinned, err := readPinnedKeys(notaryKeyPath)
	if err != nil {
		return nil, err
	}
	if _, ok := pinned[string(cp.SignerKey)]; !ok {
		return nil, fmt.Errorf("checkpoint signer key does not match pinned key")
	}
	return cp, nil
}

// readFromFile reads a JSON file containing an array of Events.
// Accepts either the raw array OR an object with an "events" field
// (mirrors the /api/v1/audit/events response shape so operators
// can `curl > events.json` and feed it back in unmodified).
// Returns events in CHAIN ORDER (oldest first) plus whether the
// --limit cap truncated the file's chain.
func readFromFile(path string, limit int) ([]*audit.Event, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	events, err := parseEventList(raw)
	if err != nil {
		return nil, false, err
	}
	// API-shaped responses come back newest-first; arrays from a
	// file might be either order. Detect by looking at the first
	// two PrevHashes: oldest-first puts the genesis (PrevHash=="")
	// at [0]; newest-first puts it at [len-1].
	if len(events) > 1 && events[0].PrevHash != "" && events[len(events)-1].PrevHash == "" {
		reverseEvents(events)
	}
	truncated := limit > 0 && len(events) > limit
	if truncated {
		events = events[:limit]
	}
	return events, truncated, nil
}

func parseEventList(raw []byte) ([]*audit.Event, error) {
	// Try array first.
	var arr []*audit.Event
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr, nil
	}
	// Try {events: [...]} envelope.
	var env struct {
		Events []*audit.Event `json:"events"`
	}
	if err := json.Unmarshal(raw, &env); err == nil && env.Events != nil {
		return env.Events, nil
	}
	return nil, errors.New("input is neither a JSON array nor an {events: [...]} object")
}

// usageErr prints "<prog>: <msg>", the usage banner, and exits 2 (CLI misuse).
func usageErr(format string, args ...any) {
	fmt.Fprintf(os.Stderr, progName+": "+format+"\n", args...)
	usage()
	os.Exit(2)
}

// errorf prints "<prog>: <msg>" and exits 1 (runtime error).
func errorf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, progName+": "+format+"\n", args...)
	os.Exit(1)
}
