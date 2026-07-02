// Package soc2report is the sso-ctl subcommand that turns a previously
// exported, tamper-evident audit bundle (see cmd/sso-ctl/auditexport)
// into a SOC2-flavored evidence pack: event counts bucketed by
// illustrative Trust-Services-Criteria control area, plus the bundle's
// own chain-verification attestation.
//
// Usage:
//
//	sso-ctl audit-export --dsn <sqlite-dsn> --out evidence.json
//	sso-ctl soc2-report --bundle evidence.json --out soc2-evidence.json
//
// It deliberately does NOT re-query a live store: it composes with
// audit-export like a Unix pipeline rather than duplicating that tool's
// pagination/DSN-opening logic a third time. Input is ALWAYS a bundle
// FILE (v1 has no stdin/live-DSN mode); --bundle - is a planned
// follow-up.
//
// MANDATORY DISCLAIMER: the control-area mapping this report applies is
// an illustrative, mechanical cross-reference from audit EventType to a
// commonly-cited SOC2 Trust Services Criterion — it is NOT a vetted
// SOC2 control mapping and has not been reviewed by qualified
// compliance or legal counsel (see platform/audit/auditreport's package
// doc for the full rationale; every report also carries this text
// verbatim in its mapping_disclaimer field).
//
// Fail-closed: the bundle is ALWAYS re-verified via
// auditreport.VerifyAndBuildSOC2Report before a report is produced. A
// bundle that fails verification (tampered, wrong format, corrupt JSON)
// produces NO output file — never a report that looks valid but was
// built over unverified evidence.
//
// Exit codes: 0 wrote a verified report (including an empty bundle),
// 1 read/parse/verify error, 2 CLI misuse.
package soc2report

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/snaplink/sso/platform/audit/auditexport"
	"github.com/snaplink/sso/platform/audit/auditreport"
)

const progName = "sso-ctl soc2-report"

const (
	flagBundle = "bundle"
	flagOut    = "out"
)

// options holds the resolved CLI inputs. run takes it by value so tests
// can drive the report core without a FlagSet or os.Exit paths.
type options struct {
	bundle, out string
}

// usageFlags is the FlagSet built in Run, referenced by the standalone
// usage banner so -h and parse errors render the flag defaults.
var usageFlags *flag.FlagSet

// Run executes the soc2-report subcommand over args (without the
// leading program name) and returns the process exit code.
func Run(args []string) int {
	var o options
	fs := flag.NewFlagSet(progName, flag.ExitOnError)
	usageFlags = fs
	fs.Usage = usage
	fs.StringVar(&o.bundle, flagBundle, "", "path to a bundle JSON file produced by sso-ctl audit-export (required)")
	fs.StringVar(&o.out, flagOut, "", "output file for the JSON report (default: stdout)")
	_ = fs.Parse(args)
	if err := validateOptions(o); err != nil {
		usageErr("%v", err)
	}
	code, err := run(o)
	if err != nil {
		errorf("%v", err)
	}
	return code
}

// validateOptions checks CLI-misuse conditions before run() ever touches
// the filesystem, so the "--bundle is required" rule is unit-testable
// without triggering usageErr's os.Exit(2).
func validateOptions(o options) error {
	if o.bundle == "" {
		return fmt.Errorf("--%s <bundle.json> is required", flagBundle)
	}
	return nil
}

// run is the testable core: it reads the bundle file, fail-closed
// verifies + builds the report, and writes it. Returns (exitCode,
// error) and never calls os.Exit.
func run(o options) (int, error) {
	raw, err := os.ReadFile(o.bundle)
	if err != nil {
		return 1, fmt.Errorf("read bundle: %w", err)
	}
	var b auditexport.ExportBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return 1, fmt.Errorf("parse bundle %s: %w", o.bundle, err)
	}
	report, err := auditreport.VerifyAndBuildSOC2Report(&b)
	if err != nil {
		// Fail-closed: write NOTHING to --out on a broken/unverified
		// bundle, matching audit-export's own "never leave a broken
		// evidence file that looks valid" convention.
		return 1, fmt.Errorf("bundle FAILED verification, refusing to report: %w", err)
	}
	if err := writeReport(o.out, report); err != nil {
		return 1, err
	}
	printSummary(report, o.out)
	return 0, nil
}

// writeReport emits report as indented JSON to out, or stdout when out
// is empty. Files are owner-only (0o600): an evidence pack aggregates
// counts derived from PII-bearing audit events.
func writeReport(out string, r *auditreport.SOC2Report) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	if out == "" {
		_, err = os.Stdout.Write(append(data, '\n'))
		return err
	}
	return os.WriteFile(out, data, 0o600)
}

// printSummary writes a one-line status to STDERR (never stdout, so a
// piped report stays clean) with only non-sensitive metadata — no event
// contents, matching audit-export's own summary convention.
func printSummary(r *auditreport.SOC2Report, out string) {
	dst := "stdout"
	if out != "" {
		dst = out
	}
	fmt.Fprintf(os.Stderr, "soc2 report written to %s (%d event(s) across %d control area(s), %d uncategorized, chain_verified=%t)\n",
		dst, r.Chain.EventCount, len(r.ControlAreas), r.Uncategorized.TotalEvents, r.Chain.Verified)
}

func usage() {
	fmt.Fprint(os.Stderr, progName+` — build a SOC2-flavored evidence pack over a previously exported, tamper-evident audit bundle.

MANDATORY DISCLAIMER: the control-area mapping this report applies is an
illustrative, mechanical cross-reference from audit EventType to a
commonly-cited SOC2 Trust Services Criterion. It is NOT a vetted SOC2
control mapping and has not been reviewed by qualified compliance or
legal counsel — see the report's own mapping_disclaimer field.

The bundle is ALWAYS re-verified before reporting; a bundle that fails
verification produces no output (exit 1).

Usage:
  `+progName+` --bundle evidence.json [--out soc2-evidence.json]

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
