// Package auditexport is the sso-ctl subcommand that extracts a filtered,
// tamper-evident bulk export of the audit hash chain into a self-contained
// JSON bundle for compliance evidence.
//
// Usage:
//
//	sso-ctl audit-export --dsn <sqlite-dsn> --since 2026-01-01T00:00:00Z --until 2026-04-01T00:00:00Z --out evidence-q1.json
//
// The bundle carries a boundary anchor so a date-range export that does
// not begin at true chain genesis stays independently verifiable via
// auditexport.VerifyExportBundle. The export is READ-ONLY: pass a
// read-only DSN (file:...?mode=ro) to inspect a live database safely,
// mirroring `sso-ctl migrate status`.
//
// A bundle may hold PII, so the tool never logs event contents — it
// prints only counts, the boundary hash, and the output path to stderr,
// keeping stdout a pure JSON bundle when --out is omitted.
//
// v1 supports the direct --dsn mode only; a --from-url mode against the
// live /api/v1/audit/events API is a planned follow-up.
//
// Exit codes: 0 wrote a verified bundle (including an empty window), 1
// load / verify error, 2 CLI misuse.
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

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/audit/auditexport"
	auditsqlite "github.com/snaplink/sso/platform/audit/sqlite"
)

const progName = "sso-ctl audit-export"

// Flag names. Filter flags use hyphenated forms of the audit query
// parameters (see platform/audit/handlers.go) so operators see one
// consistent vocabulary across audit-verify and audit-export.
const (
	flagDSN       = "dsn"
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
)

// options holds the resolved CLI inputs. run takes it by value so tests
// can drive the export core without a FlagSet or os.Exit paths.
type options struct {
	dsn, out                                            string
	typ, outcome, actorID, clientID, tenantID, provider string
	requestID, traceID, since, until                    string
	limit                                               int
}

// usageFlags is the FlagSet built in Run, referenced by the standalone
// usage banner so -h and parse errors render the flag defaults.
var usageFlags *flag.FlagSet

// Run executes the audit-export subcommand over args (without the leading
// program name) and returns the process exit code.
func Run(args []string) int {
	var o options
	fs := flag.NewFlagSet(progName, flag.ExitOnError)
	usageFlags = fs
	fs.Usage = usage
	bindFlags(fs, &o)
	_ = fs.Parse(args)
	if o.dsn == "" {
		usageErr("--" + flagDSN + " is required")
	}
	code, err := run(o)
	if err != nil {
		errorf("%v", err)
	}
	return code
}

func bindFlags(fs *flag.FlagSet, o *options) {
	fs.StringVar(&o.dsn, flagDSN, "", "SQLite DSN to export from (required; append ?mode=ro for a live DB)")
	fs.StringVar(&o.out, flagOut, "", "output file for the JSON bundle (default: stdout)")
	fs.StringVar(&o.typ, flagType, "", "filter: event type")
	fs.StringVar(&o.outcome, flagOutcome, "", "filter: outcome (success|failure)")
	fs.StringVar(&o.actorID, flagActorID, "", "filter: actor id")
	fs.StringVar(&o.clientID, flagClientID, "", "filter: client id")
	fs.StringVar(&o.tenantID, flagTenantID, "", "filter: tenant id")
	fs.StringVar(&o.provider, flagProvider, "", "filter: provider")
	fs.StringVar(&o.requestID, flagRequestID, "", "filter: request id")
	fs.StringVar(&o.traceID, flagTraceID, "", "filter: trace id")
	fs.StringVar(&o.since, flagSince, "", "filter: start of window (RFC3339 or unix seconds; inclusive)")
	fs.StringVar(&o.until, flagUntil, "", "filter: end of window (RFC3339 or unix seconds; exclusive)")
	fs.IntVar(&o.limit, flagLimit, 0, "max events to export (0 = all matching)")
}

// run is the testable core: it opens the store read-only, builds the
// self-verified bundle, and writes it. Returns (exitCode, error) and
// never calls os.Exit.
func run(o options) (int, error) {
	q, err := buildQuery(o)
	if err != nil {
		return 1, err
	}
	sink, err := auditsqlite.New(o.dsn)
	if err != nil {
		return 1, fmt.Errorf("open audit store: %w", err)
	}
	defer func() { _ = sink.Close() }()

	bundle, err := auditexport.BuildExportBundle(context.Background(), sink, q)
	if err != nil {
		return 1, err
	}
	if err := writeBundle(o.out, bundle); err != nil {
		return 1, err
	}
	printSummary(bundle, o.out)
	return 0, nil
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
	anchor := b.BoundaryPrevHash
	if anchor == "" {
		anchor = "(genesis)"
	}
	fmt.Fprintf(os.Stderr, "exported %d verified event(s) to %s (contiguous=%t, boundary_prev_hash=%s)\n",
		b.EventCount, dst, b.Contiguous, anchor)
}

func usage() {
	fmt.Fprint(os.Stderr, progName+` — export a tamper-evident bulk audit bundle for compliance evidence.

Usage:
  `+progName+` --dsn <sqlite-dsn> [filters] [--out evidence.json]

Flags:
`)
	if usageFlags != nil {
		usageFlags.PrintDefaults()
	}
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
