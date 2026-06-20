// Package snapshotcmd is the offline snapshot inspection + verification
// subcommand of sso-ctl — useful for backup-pipeline integrity checks and
// disaster-recovery drills where the live admin gRPC API isn't reachable.
//
// Subcommands:
//
//	sso-ctl snapshot list    --dir /var/lib/sso/snapshots
//	sso-ctl snapshot inspect --dir /var/lib/sso/snapshots --id <id>
//	sso-ctl snapshot verify  --dir /var/lib/sso/snapshots --id <id>
//	                                                       [--passphrase=X | --passphrase-file=P]
//
// All subcommands operate directly against the file storage
// backend — no SSO server needs to be running. `list` + `inspect`
// only touch the unencrypted envelope header; `verify` runs the
// full Pipeline.Load including checksum validation + decryption.
package snapshotcmd

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/snaplink/sso/interfaces/snapshot"
	encryptionnone "github.com/snaplink/sso/interfaces/snapshot/encryptionnone"
	encryptionpass "github.com/snaplink/sso/interfaces/snapshot/encryptionpassphrase"
	storagefile "github.com/snaplink/sso/interfaces/snapshot/storagefile"
)

const progName = "sso-snapshotctl"

// Run executes the snapshot subcommand with args (program name already
// stripped) and returns the process exit code. Mirrors the original
// main() dispatch verbatim: os.Exit(n) becomes return n.
func Run(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	cmd := args[0]
	rest := args[1:]
	var err error
	switch cmd {
	case "list":
		err = runList(rest)
	case "inspect":
		err = runInspect(rest)
	case "verify":
		err = runVerify(rest)
	case "-h", "--help", "help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, progName+": unknown subcommand %q\n", cmd)
		usage()
		return 2
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, progName+": %v\n", err)
		return 1
	}
	return 0
}

// usage prints the standard "<prog> — <desc> / Usage / Subcommands" banner.
func usage() {
	fmt.Fprintln(os.Stderr, progName+` — offline snapshot inspection + verification.

Usage:
  `+progName+` <subcommand> [flags]

Subcommands:
  list     List snapshot ids in a storage directory.
  inspect  Print the envelope header for one snapshot (no decryption).
  verify   Load + decrypt + checksum-verify one snapshot.

Run "`+progName+` <subcommand> -h" for subcommand flags.`)
}

func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	dir := fs.String("dir", "", "snapshot storage directory (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("--dir is required")
	}
	store, err := storagefile.New(*dir)
	if err != nil {
		return fmt.Errorf("open storage: %w", err)
	}
	names, err := store.List(context.Background())
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}
	if len(names) == 0 {
		fmt.Println("(no snapshots)")
		return nil
	}
	// Render a small table: NAME, SIZE, ALGORITHM, CODEC. Peek
	// each envelope to surface header metadata. Skip silently on
	// individual peek failures so a single bad file doesn't hide
	// the rest from operators triaging a backup.
	fmt.Printf("%-40s  %-10s  %-12s  %s\n", "ID", "SIZE", "ALG", "CODEC")
	for _, name := range names {
		raw, err := store.Get(context.Background(), name)
		if err != nil {
			fmt.Printf("%-40s  %-10s  %-12s  %s  (get error: %v)\n", name, "?", "?", "?", err)
			continue
		}
		env, perr := snapshot.PeekEnvelope(raw)
		if perr != nil {
			fmt.Printf("%-40s  %-10d  %-12s  %s  (peek error: %v)\n", name, len(raw), "?", "?", perr)
			continue
		}
		alg := env.Algorithm
		if alg == "" {
			alg = "none"
		}
		fmt.Printf("%-40s  %-10d  %-12s  %s\n", env.SnapshotID, len(raw), alg, env.Codec)
	}
	return nil
}

func runInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	dir := fs.String("dir", "", "snapshot storage directory (required)")
	id := fs.String("id", "", "snapshot id (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *id == "" {
		return errors.New("--dir and --id are required")
	}
	store, err := storagefile.New(*dir)
	if err != nil {
		return fmt.Errorf("open storage: %w", err)
	}
	raw, err := store.Get(context.Background(), *id)
	if err != nil {
		return fmt.Errorf("get %q: %w", *id, err)
	}
	env, err := snapshot.PeekEnvelope(raw)
	if err != nil {
		return fmt.Errorf("peek: %w", err)
	}
	// Render the envelope header as JSON so operators can grep /
	// jq it programmatically. Body stays cleared by PeekEnvelope.
	out, err := json.MarshalIndent(struct {
		FileBytes           int    `json:"file_bytes"`
		EnvelopeVersion     string `json:"envelope_version"`
		SnapshotID          string `json:"snapshot_id"`
		Codec               string `json:"codec"`
		EncryptionAlgorithm string `json:"encryption_algorithm"`
		HasEncryptionParams bool   `json:"has_encryption_params"`
		PlaintextSHA256     string `json:"plaintext_sha256_hex"`
	}{
		FileBytes:           len(raw),
		EnvelopeVersion:     env.EnvelopeVersion,
		SnapshotID:          env.SnapshotID,
		Codec:               env.Codec,
		EncryptionAlgorithm: env.Algorithm,
		HasEncryptionParams: len(env.EncryptionParams) > 0,
		PlaintextSHA256:     env.ChecksumSHA256,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	fmt.Println(string(out))
	return nil
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	dir := fs.String("dir", "", "snapshot storage directory (required)")
	id := fs.String("id", "", "snapshot id (required)")
	pass := fs.String("passphrase", "", "passphrase for encrypted snapshots")
	passFile := fs.String("passphrase-file", "", "path to a file containing the passphrase (one line)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *id == "" {
		return errors.New("--dir and --id are required")
	}
	passphrase, err := resolvePassphrase(*pass, *passFile)
	if err != nil {
		return err
	}

	store, err := storagefile.New(*dir)
	if err != nil {
		return fmt.Errorf("open storage: %w", err)
	}
	raw, err := store.Get(context.Background(), *id)
	if err != nil {
		return fmt.Errorf("get %q: %w", *id, err)
	}
	env, err := snapshot.PeekEnvelope(raw)
	if err != nil {
		return fmt.Errorf("peek: %w", err)
	}

	sealer, err := sealerForEnvelope(env.Algorithm, passphrase)
	if err != nil {
		return err
	}

	pipe := &snapshot.Pipeline{Sealer: sealer}
	snap, err := pipe.Load(context.Background(), store, *id)
	if err != nil {
		return fmt.Errorf("load: %w", err)
	}
	printVerifyResult(env, snap)
	return nil
}

// resolvePassphrase reconciles the mutually-exclusive --passphrase /
// --passphrase-file flags into a single value, reading the file (trimming a
// trailing newline) when that form is used.
func resolvePassphrase(pass, passFile string) (string, error) {
	if pass != "" && passFile != "" {
		return "", errors.New("--passphrase and --passphrase-file are mutually exclusive")
	}
	if passFile == "" {
		return pass, nil
	}
	raw, err := os.ReadFile(passFile)
	if err != nil {
		return "", fmt.Errorf("read passphrase file: %w", err)
	}
	return strings.TrimRight(string(raw), "\r\n"), nil
}

// sealerForEnvelope picks the unseal strategy for an envelope's encryption
// algorithm. Unencrypted envelopes keep the no-op sealer (noting an ignored
// passphrase); encrypted ones require a passphrase.
func sealerForEnvelope(algorithm, pass string) (snapshot.Sealer, error) {
	switch algorithm {
	case "", encryptionnone.New().Algorithm():
		if pass != "" {
			fmt.Fprintln(os.Stderr, "note: --passphrase ignored — envelope is unencrypted")
		}
		return encryptionnone.New(), nil
	default:
		if pass == "" {
			return nil, fmt.Errorf("envelope is encrypted with %q; supply --passphrase or --passphrase-file", algorithm)
		}
		return encryptionpass.NewFromString(pass), nil
	}
}

// printVerifyResult renders the success summary for a loaded snapshot:
// envelope metadata plus a per-resource item count.
func printVerifyResult(env snapshot.SealedEnvelope, snap *snapshot.Snapshot) {
	res := snap.Resources
	counts := map[string]int{
		"clients":     len(res.Clients),
		"users":       len(res.Users),
		"roles":       len(res.Roles),
		"assignments": len(res.Assignments),
		"menus":       len(res.Menus),
		"netpolicy":   len(res.NetPolicy),
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	taken := time.Unix(snap.TakenAtUnix, 0).UTC().Format(time.RFC3339)
	fmt.Printf("ok: snapshot %q decrypted + checksum verified\n", env.SnapshotID)
	fmt.Printf("    codec:          %s\n", env.Codec)
	fmt.Printf("    algorithm:      %s\n", env.Algorithm)
	fmt.Printf("    taken_at:       %s\n", taken)
	fmt.Printf("    schema_version: %s\n", snap.SchemaVersion)
	fmt.Printf("    resources:      %d items total\n", total)
	for _, k := range []string{"clients", "users", "roles", "assignments", "menus", "netpolicy"} {
		fmt.Printf("                    %-12s %d\n", k+":", counts[k])
	}
}
