// Package hashcmd is the password-hashing subcommand for sso-ctl. It produces a
// password hash in the SAME encoding the server's password authenticator
// verifies, so operators can seed an initial admin credential or build an
// import CSV without a running server.
//
// Usage:
//
//	sso-ctl hash --password 's3cret'        # hash a literal (avoid in shared shells)
//	sso-ctl hash                            # read the password from stdin (no echo on a TTY is NOT guaranteed; pipe it)
//	echo -n 's3cret' | sso-ctl hash
//
// The default format is bcrypt (what the server upgrades legacy hashes to).
// The output is the bare encoded hash on stdout, suitable for the import CSV's
// password_hash column or a config seed.
package hashcmd

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/yangwb1123/snaplink/domains/authenticators"
)

const progName = "sso-ctl hash"

// Run is the hash subcommand entry point. args has the leading program name
// stripped (the dispatcher's os.Args[2:]). It returns the process exit code.
func Run(args []string) int {
	fs := flag.NewFlagSet("hash", flag.ContinueOnError)
	password := fs.String("password", "", "the plaintext to hash (omit to read from stdin)")
	quiet := fs.Bool("quiet", false, "print only the hash (no format label)")
	fs.Usage = usage
	if err := fs.Parse(args); err != nil {
		return 2
	}

	plain, err := readPassword(*password, os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, progName+": %v\n", err)
		return 2
	}
	if plain == "" {
		fmt.Fprintln(os.Stderr, progName+": empty password")
		return 2
	}

	h, err := authenticators.HashPassword(plain)
	if err != nil {
		fmt.Fprintf(os.Stderr, progName+": hash: %v\n", err)
		return 1
	}
	if *quiet {
		fmt.Println(h.Hash)
	} else {
		fmt.Printf("format: %s\nhash:   %s\n", h.Format, h.Hash)
	}
	return 0
}

// readPassword returns the literal flag value when set, otherwise reads a
// single line (trailing newline trimmed) from r. Splitting it out keeps the
// stdin path unit-testable.
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

func usage() {
	fmt.Fprintln(os.Stderr, progName+` — produce a server-compatible password hash.

Usage:
  `+progName+` --password <plaintext> [--quiet]
  echo -n <plaintext> | `+progName+`

Flags:
  --password   The plaintext to hash (omit to read one line from stdin).
  --quiet      Print only the hash, no "format:/hash:" labels.

Examples:
  `+progName+` --password 'change-me' --quiet
  echo -n 'change-me' | `+progName+``)
}
