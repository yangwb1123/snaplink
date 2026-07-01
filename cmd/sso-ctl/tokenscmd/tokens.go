// Package tokenscmd implements sso-ctl token management subcommands.
//
// Usage:
//
//	sso-ctl tokens revoke <token-jti>
//	sso-ctl tokens issue-temp --user=<id> [--ttl=5m]
package tokenscmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/snaplink/sso/cmd/sso-ctl/apiclient"
)

const progName = "sso-ctl tokens"

// Run is the tokens subcommand entry point. args excludes the leading
// "tokens" token. Returns the process exit code.
func Run(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	switch args[0] {
	case "revoke":
		return runRevoke(args[1:])
	case "issue-temp":
		return runIssueTemp(args[1:])
	case "-h", "--help", "help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "%s: unknown subcommand %q\n", progName, args[0])
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprint(os.Stderr, progName+` — manage tokens.

Usage:
  `+progName+` revoke <token-jti>
  `+progName+` issue-temp --user=<id> [--ttl=5m]

Subcommands:
  revoke      Revoke an access token by its JTI.
  issue-temp  Issue a temporary one-time token (for password resets, etc.).

Flags:
  --user   User ID to issue the temp token for (required for issue-temp).
  --ttl    Token TTL (default: 5m).

Examples:
  `+progName+` revoke tok_jti_abc123
  `+progName+` issue-temp --user=user123
  `+progName+` issue-temp --user=user123 --ttl=15m
`)
}

func runRevoke(args []string) int {
	if len(args) < 1 || args[0] == "" {
		fmt.Fprintln(os.Stderr, progName+": token JTI is required")
		usage()
		return 2
	}
	tokenJTI := args[0]

	client := apiclient.New()
	resp, err := client.Post("/api/v1/admin/tokens/revoke", map[string]string{
		"token": tokenJTI,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: revoke failed: %v\n", progName, err)
		return 1
	}
	body, err := apiclient.ReadBody(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", progName, err)
		return 1
	}
	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "%s: revoke failed (HTTP %d): %s\n", progName, resp.StatusCode, string(body))
		return 1
	}
	fmt.Printf("token %q revoked\n", tokenJTI)
	return 0
}

func runIssueTemp(args []string) int {
	fs := flag.NewFlagSet("issue-temp", flag.ContinueOnError)
	userID := fs.String("user", "", "user ID (required)")
	ttl := fs.String("ttl", "5m", "token TTL (e.g. 5m, 1h)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *userID == "" {
		fmt.Fprintln(os.Stderr, progName+": --user is required")
		usage()
		return 2
	}
	ttlDur, err := time.ParseDuration(*ttl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: invalid --ttl %q: %v\n", progName, *ttl, err)
		return 2
	}

	client := apiclient.New()
	resp, err := client.Post("/api/v1/admin/tokens/temp", map[string]any{
		"user_id": *userID,
		"ttl":     ttlDur.String(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: issue-temp failed: %v\n", progName, err)
		return 1
	}
	body, err := apiclient.ReadBody(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", progName, err)
		return 1
	}
	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "%s: issue-temp failed (HTTP %d): %s\n", progName, resp.StatusCode, string(body))
		return 1
	}
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Fprintf(os.Stderr, "%s: parse response: %v\n", progName, err)
		return 1
	}
	apiclient.WriteJSON(result)
	return 0
}
