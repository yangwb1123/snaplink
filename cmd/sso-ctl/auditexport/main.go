// Package auditexport is the sso-ctl subcommand that extracts a filtered,
// tamper-evident bulk export of the audit hash chain into a self-contained
// JSON bundle for compliance evidence, and offline-verifies such a bundle.
//
// Usage:
//
//	sso-ctl audit-export --dsn <sqlite-dsn> --since 2026-01-01T00:00:00Z --until 2026-04-01T00:00:00Z --out evidence-q1.json
//	sso-ctl audit-export --verify evidence-q1.json
//
// The bundle carries a boundary anchor so a date-range export that does
// not begin at true chain genesis stays independently verifiable via
// auditexport.VerifyExportBundle. The --verify mode re-runs that check on
// a finished bundle file with no store access, so an auditor who received
// only the JSON can confirm it is untampered.
//
// The export is strictly READ-ONLY: the store is opened via
// auditsqlite.OpenReadOnly, which NEVER migrates the schema — so a
// read-only DSN (file:...?mode=ro) works, and a read-write DSN is never
// write-locked or schema-mutated by this tool. A schema whose version does
// not match the binary is reported, never migrated.
//
// A bundle may hold PII, so the tool never logs event contents — it
// prints only counts, the boundary hash, and the output path to stderr,
// keeping stdout a pure JSON bundle when --out is omitted.
//
// v1 supports the direct --dsn mode only; a --from-url mode against the
// live /api/v1/audit/events API is a planned follow-up.
//
// A bundle can be anchored to a signed notary checkpoint (--anchor): the
// export embeds the attestation only when the bundle ends exactly at the
// attested chain head (fail-closed — checkpoints attest chain heads
// only), and --verify enforces the checkpoint signature plus exact head
// equality. An explicit --anchor file wins over the bundle's embedded
// copy; without either, verification is legacy (the self-referential
// head check only — the residual risk this anchor closes). The embedded
// copy alone is a self-contained convenience record, not enforcement:
// a bundle writer can forge it, so evidence-grade verification requires
// the flag.
//
// Exit codes: 0 wrote / verified a clean bundle (including an empty
// window), 1 load / verify error (incl. a tampered bundle, and an
// invalid or mismatched --anchor), 2 CLI misuse (incl. an unrecognized
// --outcome value).
package auditexport

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/audit/auditexport"
	"github.com/yangwb1123/snaplink/platform/audit/auditspi"
	auditsqlite "github.com/yangwb1123/snaplink/platform/audit/sqlite"
)

const progName = "sso-ctl audit-export"

// Flag names. Filter flags use hyphenated forms of the audit query
// parameters (see platform/audit/handlers.go) so operators see one
// consistent vocabulary across audit-verify and audit-export.
const (
	flagDSN       = "dsn"
	flagVerify    = "verify"
	flagOut       = "out"
	flagType      = "type"
	flagOutcome   = "outcome"
	flagActorID   = "actor-id"
	flagClientID  = "client-id"
	flagTenantID  = "tenant-id"
	flagProvider  = "provider"
	flagRequestID = "request-id"
	flagTraceID   = "trace-id"
	flagSince     = "since"
	flagUntil     = "until"
	flagLimit     = "limit"
	flagAnchor    = "anchor"
)

// options holds the resolved CLI inputs. run takes it by value so tests
// can drive the export core without a FlagSet or os.Exit paths.
type options struct {
	dsn, verify, out                                    string
	typ, outcome, actorID, clientID, tenantID, provider string
	requestID, traceID, since, until                    string
	limit                                               int
	anchor                                              string
}

// usageFlags is the FlagSet built in Run, referenced by the standalone
// usage banner so -h and parse errors render the flag defaults.
var usageFlags *flag.FlagSet

// Run executes the audit-export subcommand over args (without the leading
// program name) and returns the process exit code; the caller
// (cmd/sso-ctl main) exits with it. It is the single exit-code decision
// point: misuse errors print the usage banner (code 2), runtime errors
// print the message only (code 1), and neither path calls os.Exit.
func Run(args []string) int {
	var o options
	fs := flag.NewFlagSet(progName, flag.ExitOnError)
	usageFlags = fs
	fs.Usage = usage
	bindFlags(fs, &o)
	_ = fs.Parse(args)
	code, err := dispatch(o)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", progName, err)
		if code == 2 {
			usage()
		}
	}
	return code
}

// dispatch routes to offline-verify (--verify) or export (--dsn). The two
// modes are mutually exclusive: --verify reads a finished bundle file and
// needs no store, so pairing it with --dsn is a usage error; exactly one
// of the two must be given. CLI misuse returns (2, err) so Run is the
// single exit decision point — os.Exit here would be untestable in
// process. validateOutcome runs before every mode branch so both --dsn
// and --verify runs reject an unknown --outcome.
func dispatch(o options) (int, error) {
	if err := validateOutcome(o.outcome); err != nil {
		return 2, err
	}
	if o.verify != "" {
		if o.dsn != "" {
			return 2, usageErrorf("--%s and --%s are mutually exclusive", flagVerify, flagDSN)
		}
		return runVerify(o.verify, o.anchor)
	}
	if o.dsn == "" {
		return 2, usageErrorf("--%s (export) or --%s <bundle> (offline verify) is required", flagDSN, flagVerify)
	}
	return run(o)
}

func bindFlags(fs *flag.FlagSet, o *options) {
	fs.StringVar(&o.dsn, flagDSN, "", "SQLite DSN to export from (required for export; opened read-only, append ?mode=ro for a live DB)")
	fs.StringVar(&o.verify, flagVerify, "", "offline-verify a bundle file instead of exporting (no --dsn); non-zero exit on tamper")
	fs.StringVar(&o.out, flagOut, "", "output file for the JSON bundle (default: stdout)")
	fs.StringVar(&o.typ, flagType, "", "filter: event type (unrecognized values warn; custom types allowed)")
	fs.StringVar(&o.outcome, flagOutcome, "", "filter: outcome (success|failure; unrecognized value is a usage error)")
	fs.StringVar(&o.actorID, flagActorID, "", "filter: actor id")
	fs.StringVar(&o.clientID, flagClientID, "", "filter: client id")
	fs.StringVar(&o.tenantID, flagTenantID, "", "filter: tenant id")
	fs.StringVar(&o.provider, flagProvider, "", "filter: provider")
	fs.StringVar(&o.requestID, flagRequestID, "", "filter: request id")
	fs.StringVar(&o.traceID, flagTraceID, "", "filter: trace id")
	fs.StringVar(&o.since, flagSince, "", "filter: start of window (RFC3339 or unix seconds; inclusive)")
	fs.StringVar(&o.until, flagUntil, "", "filter: end of window (RFC3339 or unix seconds; exclusive)")
	fs.IntVar(&o.limit, flagLimit, 0, "max events to export (0 = all matching)")
	fs.StringVar(&o.anchor, flagAnchor, "", "signed notary checkpoint (JSON) to bind this evidence to (export: embedded into the bundle; verify: checked against the bundle head)")
}

// run is the testable core: it opens the store read-only, builds the
// self-verified bundle, and writes it. Returns (exitCode, error) and
// never calls os.Exit. With --anchor the checkpoint is loaded and
// signature-checked BEFORE the store opens (fail-fast, mirroring the
// validateOutcome-first discipline), and head equality is enforced
// before the bundle is written, so a mismatched anchor never leaves a
// bundle file behind.
func run(o options) (int, error) {
	q, err := buildQuery(o)
	if err != nil {
		return 1, err
	}
	warnUnknownType(o.typ)
	var cp *audit.SignedCheckpoint
	if o.anchor != "" {
		cp, err = loadCheckpoint(o.anchor)
		if err != nil {
			return 1, err
		}
	}
	// OpenReadOnly never migrates: a read-only DSN works and a live
	// read-write store is never write-locked or schema-mutated by an
	// export. Using New here would BEGIN IMMEDIATE + apply DDL — a write
	// from a read-only tool.
	sink, err := auditsqlite.OpenReadOnly(o.dsn)
	if err != nil {
		return 1, fmt.Errorf("open audit store: %w", err)
	}
	defer func() { _ = sink.Close() }()

	bundle, err := auditexport.BuildExportBundle(context.Background(), sink, q)
	if err != nil {
		return 1, err
	}
	if cp != nil {
		if err := enforceAnchorHead(bundle.HeadHash, cp); err != nil {
			return 1, err
		}
		bundle.Anchor = cp
	}
	if err := writeBundle(o.out, bundle); err != nil {
		return 1, err
	}
	printSummary(bundle, o.out)
	return 0, nil
}

// runVerify loads a previously exported bundle file and re-verifies it
// offline (no store access), so the recipient of a JSON evidence file can
// confirm it is untampered. Returns (0,nil) on a clean bundle and (1,err)
// on any load / parse failure or verification break so the process exits
// non-zero on tamper.
//
// Anchor resolution: VerifyExportBundle runs FIRST (a byte-tampered
// bundle fails at the chain check regardless of any anchor); then an
// explicit --anchor file wins over the bundle's embedded Anchor; both
// present and byte-different is a conflicting-anchors error; a resolved
// checkpoint is signature-checked (the flag path already did so during
// load) and its attested head must equal the bundle head exactly.
func runVerify(path, anchorPath string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 1, fmt.Errorf("read bundle: %w", err)
	}
	var b auditexport.ExportBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return 1, fmt.Errorf("parse bundle %s: %w", path, err)
	}
	if err := auditexport.VerifyExportBundle(&b); err != nil {
		return 1, fmt.Errorf("bundle FAILED verification: %w", err)
	}
	var cp *audit.SignedCheckpoint
	fromFlag := false
	if anchorPath != "" {
		cp, err = loadCheckpoint(anchorPath)
		if err != nil {
			return 1, err
		}
		fromFlag = true
	} else if b.Anchor != nil {
		cp = b.Anchor
	}
	if cp == nil {
		printVerifyOK(&b, nil, false)
		return 0, nil
	}
	if fromFlag && b.Anchor != nil && !audit.CheckpointEqual(cp, b.Anchor) {
		return 1, fmt.Errorf("conflicting anchors: --%s file and embedded bundle anchor differ", flagAnchor)
	}
	if !fromFlag {
		// The embedded copy is forgeable by a bundle writer (no key
		// registry), so this is the single enforcement point for it.
		if err := audit.VerifyCheckpointSignature(cp); err != nil {
			return 1, fmt.Errorf("embedded anchor FAILED signature check: %w", err)
		}
	}
	if err := enforceAnchorHead(b.HeadHash, cp); err != nil {
		return 1, err
	}
	printVerifyOK(&b, cp, fromFlag)
	return 0, nil
}

// loadCheckpoint reads a SignedCheckpoint JSON file exactly once and
// returns the in-memory struct, so the signature check and head equality
// run over the same bytes (no re-read, no TOCTOU). The signature is
// enforced here for the flag path: a checkpoint a store tamperer could
// not re-sign is the only enforcement-grade anchor.
func loadCheckpoint(path string) (*audit.SignedCheckpoint, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read anchor %s: %w", path, err)
	}
	var cp audit.SignedCheckpoint
	if err := json.Unmarshal(raw, &cp); err != nil {
		return nil, fmt.Errorf("parse anchor %s: %w", path, err)
	}
	if err := audit.VerifyCheckpointSignature(&cp); err != nil {
		return nil, fmt.Errorf("anchor %s FAILED signature check: %w", path, err)
	}
	return &cp, nil
}

// enforceAnchorHead is the single head-equality check for both modes:
// checkpoints attest chain heads only, so exact equality is the only
// sound offline relation (an empty bundle's "" equals GenesisHash, the
// notary's empty-chain convention). Failing closed on mismatch is what
// makes an anchored bundle evidence rather than a re-attestable claim.
func enforceAnchorHead(head string, cp *audit.SignedCheckpoint) error {
	if head != cp.Checkpoint.HeadHash {
		return fmt.Errorf("anchor head mismatch: bundle head_hash %q, checkpoint attestation %q (checkpoints attest chain heads only)",
			head, cp.Checkpoint.HeadHash)
	}
	return nil
}

func buildQuery(o options) (audit.Query, error) {
	q := audit.Query{
		Type:      audit.EventType(o.typ),
		Outcome:   audit.Outcome(o.outcome),
		ActorID:   o.actorID,
		ClientID:  o.clientID,
		TenantID:  o.tenantID,
		Provider:  o.provider,
		RequestID: o.requestID,
		TraceID:   o.traceID,
		Limit:     o.limit,
	}
	if o.since != "" {
		t, err := parseTime(o.since)
		if err != nil {
			return q, fmt.Errorf("--%s: %w", flagSince, err)
		}
		q.Since = t
	}
	if o.until != "" {
		t, err := parseTime(o.until)
		if err != nil {
			return q, fmt.Errorf("--%s: %w", flagUntil, err)
		}
		q.Until = t
	}
	return q, nil
}

// parseTime accepts RFC3339 or unix seconds — duplicated from the audit
// HTTP handler's unexported helper (deliberate isolation, not a shared
// import) so this offline tool has no dependency on the delivery edge.
func parseTime(v string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.Unix(n, 0), nil
	}
	return time.Time{}, errors.New("expected RFC3339 timestamp or unix seconds")
}

// writeBundle emits the bundle as indented JSON to out, or stdout when
// out is empty. Files are owner-only (0o600): an evidence bundle may hold
// PII.
func writeBundle(out string, b *auditexport.ExportBundle) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal bundle: %w", err)
	}
	if out == "" {
		_, err = os.Stdout.Write(append(data, '\n'))
		return err
	}
	return os.WriteFile(out, data, 0o600)
}

// printSummary writes a one-line status to STDERR (never stdout, so a
// piped bundle stays clean) with only non-sensitive metadata — no event
// contents.
func printSummary(b *auditexport.ExportBundle, out string) {
	dst := "stdout"
	if out != "" {
		dst = out
	}
	fmt.Fprintf(os.Stderr, "exported %d verified event(s) to %s (contiguous=%t, boundary_prev_hash=%s)\n",
		b.EventCount, dst, b.Contiguous, anchorLabel(b))
}

// printVerifyOK writes the offline-verify pass summary to STDERR with only
// non-sensitive counts — no event contents. When an anchor was enforced,
// the line names its attested head; when that anchor came from the
// bundle's embedded copy (no --anchor flag), the line also warns that the
// embedded path is convenience, not enforcement-grade (a bundle writer
// can forge it).
func printVerifyOK(b *auditexport.ExportBundle, cp *audit.SignedCheckpoint, fromFlag bool) {
	line := fmt.Sprintf("bundle verified: %d event(s) (contiguous=%t, boundary_prev_hash=%s, head_hash=%s)",
		b.EventCount, b.Contiguous, anchorLabel(b), b.HeadHash)
	if cp != nil {
		line += fmt.Sprintf(", anchor_head=%s", cp.Checkpoint.HeadHash)
		if !fromFlag {
			line += ", warning=embedded-anchor-not-enforcement-grade"
		}
	}
	fmt.Fprintln(os.Stderr, line)
}

// anchorLabel renders the boundary anchor for a summary line, naming the
// empty genesis anchor explicitly so a reader doesn't mistake it for a
// missing value.
func anchorLabel(b *auditexport.ExportBundle) string {
	if b.BoundaryPrevHash == "" {
		return "(genesis)"
	}
	return b.BoundaryPrevHash
}

func usage() {
	fmt.Fprint(os.Stderr, progName+` — export or offline-verify a tamper-evident bulk audit bundle for compliance evidence.

Usage:
  `+progName+` --dsn <sqlite-dsn> [filters] [--out evidence.json]
  `+progName+` --verify <bundle.json>

Flags:
`)
	if usageFlags != nil {
		usageFlags.PrintDefaults()
	}
}

// validateOutcome enforces the closed --outcome vocabulary. Empty is the
// wildcard; values are compared against the audit constants, never
// literals, because the vocabulary is closed (no custom outcomes exist).
func validateOutcome(v string) error {
	if v == "" || audit.Outcome(v) == audit.OutcomeSuccess || audit.Outcome(v) == audit.OutcomeFailure {
		return nil
	}
	return fmt.Errorf("--%s: %q is not a valid outcome (allowed: %s|%s)",
		flagOutcome, v, audit.OutcomeSuccess, audit.OutcomeFailure)
}

// warnUnknownType surfaces a likely --type typo on stderr. Custom event
// types are legal (auditspi.EventType doc), so this warns only, mirroring
// serverbuildauthn.warnUnknownAuditEventTypes (build_audit_webhook.go) —
// the registry is a filter/UX aid, never a record-path gate.
func warnUnknownType(typ string) {
	if typ == "" {
		return
	}
	if _, known := auditspi.KnownEventTypes[auditspi.EventType(typ)]; known {
		return
	}
	fmt.Fprintf(os.Stderr, "%s: warning: --%s %q is not a registered sso event type (custom event types are allowed; check spelling)\n",
		progName, flagType, typ)
}

// usageErrorf formats a CLI-misuse diagnostic. The progName prefix is NOT
// embedded — Run adds exactly one when it prints, reproducing the old
// usageErr output; embedding it here would double-print it. Returns the
// error so misuse flows back through dispatch as exit code 2 instead of
// an in-process os.Exit.
func usageErrorf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}
