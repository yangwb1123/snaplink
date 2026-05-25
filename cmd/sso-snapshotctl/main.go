// sso-snapshotctl is an operator CLI for offline snapshot
// inspection + verification — useful for backup-pipeline integrity
// checks and disaster-recovery drills where the live admin gRPC
// API isn't reachable.
//
// Subcommands:
//
//	sso-snapshotctl list    --dir /var/lib/sso/snapshots
//	sso-snapshotctl inspect --dir /var/lib/sso/snapshots --id <id>
//	sso-snapshotctl verify  --dir /var/lib/sso/snapshots --id <id>
//	                                                     [--passphrase=X | --passphrase-file=P]
//
// All subcommands operate directly against the file storage
// backend — no SSO server needs to be running. `list` + `inspect`
// only touch the unencrypted envelope header; `verify` runs the
// full Pipeline.Load including checksum validation + decryption.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/snaplink/sso/snapshot"
	encryptionnone "github.com/snaplink/sso/snapshot/encryption/none"
	encryptionpass "github.com/snaplink/sso/snapshot/encryption/passphrase"
	storagefile "github.com/snaplink/sso/snapshot/storage/file"
)

const progName = "sso-snapshotctl"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	rest := os.Args[2:]
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
		return
	default:
		fmt.Fprintf(os.Stderr, progName+": unknown subcommand %q\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, progName+": %v\n", err)
		os.Exit(1)
	}
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
	if *pass != "" && *passFile != "" {
		return errors.New("--passphrase and --passphrase-file are mutually exclusive")
	}
	if *passFile != "" {
		raw, err := os.ReadFile(*passFile)
		if err != nil {
			return fmt.Errorf("read passphrase file: %w", err)
		}
		*pass = strings.TrimRight(string(raw), "\r\n")
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

	var sealer snapshot.Sealer = encryptionnone.New()
	switch env.Algorithm {
	case "", encryptionnone.New().Algorithm():
		// None / unset — keep the no-op sealer.
		if *pass != "" {
			fmt.Fprintln(os.Stderr, "note: --passphrase ignored — envelope is unencrypted")
		}
	default:
		if *pass == "" {
			return fmt.Errorf("envelope is encrypted with %q; supply --passphrase or --passphrase-file", env.Algorithm)
		}
		sealer = encryptionpass.NewFromString(*pass)
	}

	pipe := &snapshot.Pipeline{Sealer: sealer}
	snap, err := pipe.Load(context.Background(), store, *id)
	if err != nil {
		return fmt.Errorf("load: %w", err)
	}
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
	return nil
}
