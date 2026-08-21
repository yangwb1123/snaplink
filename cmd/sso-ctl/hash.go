// Password hashing is kept in the composition root because it is a small
// operator-tool command, not a reusable command package. Keeping it here also
// avoids another top-level command directory in the toolbelt.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/yangwb1123/snaplink/domains/authenticators"
)

const hashProgName = "sso-ctl hash"

// runHash is the hash subcommand entry point. args has the leading program
// name stripped (the dispatcher's os.Args[2:]).
func runHash(args []string) int {
	fs := flag.NewFlagSet("hash", flag.ContinueOnError)
	password := fs.String("password", "", "the plaintext to hash (omit to read from stdin)")
	quiet := fs.Bool("quiet", false, "print only the hash (no format label)")
	fs.Usage = hashUsage
	if err := fs.Parse(args); err != nil {
		return 2
	}

	plain, err := readPassword(*password, os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, hashProgName+": %v\n", err)
		return 2
	}
	if plain == "" {
		fmt.Fprintln(os.Stderr, hashProgName+": empty password")
		return 2
	}

	h, err := authenticators.HashPassword(plain)
	if err != nil {
		fmt.Fprintf(os.Stderr, hashProgName+": hash: %v\n", err)
		return 1
	}
	if *quiet {
		fmt.Println(h.Hash)
	} else {
		fmt.Printf("format: %s\nhash:   %s\n", h.Format, h.Hash)
	}
	return 0
}

func readPassword(flagVal string, r io.Reader) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read stdin: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func hashUsage() {
	fmt.Fprintln(os.Stderr, hashProgName+` — produce a server-compatible password hash.

Usage:
  `+hashProgName+` --password <plaintext> [--quiet]
  echo -n <plaintext> | `+hashProgName+`

Flags:
  --password   The plaintext to hash (omit to read one line from stdin).
  --quiet      Print only the hash, no "format:/hash:" labels.

Examples:
  `+hashProgName+` --password 'change-me' --quiet
  echo -n 'change-me' | `+hashProgName+``)
}
