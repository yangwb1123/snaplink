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

	"github.com/yangwb1123/snaplink/cmd/sso-ctl/apiclient"
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
  --ttl    Requested token TTL (e.g. 5m, 1h). NOT currently enforced by the
           server — the actual TTL is fixed by server config. Passing this
           prints a warning rather than silently doing nothing.

Examples:
  `+progName+` revoke tok_jti_abc123
  `+progName+` issue-temp --user=user123
`)
}

func runRevoke(args []string) int {
	if len(args) < 1 || args[0] == "" {
		fmt.Fprintln(os.Stderr, progName+": token JTI is required")
		usage()
		return 2
	}
	tokenJTI := args[0]

	client := apiclient.New(apiclient.WithNoRedirect())
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
		fmt.Fprintln(os.Stderr, apiclient.StatusMessage(progName, "revoke", apiclient.RedirectHintAdmin, resp, body))
		return 1
	}
	fmt.Printf("token %q revoked\n", tokenJTI)
	return 0
}

// checkTTLFlag validates a raw --ttl value and warns that it has no
// server-side effect. Returns 0 to continue, or a nonzero exit code the
// caller should return immediately (invalid duration ⇒ 2).
func checkTTLFlag(ttl string) int {
	if ttl == "" {
		return 0
	}
	if _, err := time.ParseDuration(ttl); err != nil {
		fmt.Fprintf(os.Stderr, "%s: invalid --ttl %q: %v\n", progName, ttl, err)
		return 2
	}
	fmt.Fprintf(os.Stderr, "%s: warning: --ttl is not enforced by the server; the issued token's actual TTL is fixed by server config (see expiresAtUnix in the response below)\n", progName)
	return 0
}

func runIssueTemp(args []string) int {
	fs := flag.NewFlagSet("issue-temp", flag.ContinueOnError)
	userID := fs.String("user", "", "user ID (required)")
	// NOTE: adminv1.IssueTempTokenRequest (proto/admin/v1/tokens.proto) has
	// no ttl field, and the gRPC-gateway's protojson unmarshaler discards
	// unknown JSON fields — so a "ttl" sent in the request body is silently
	// ignored server-side; the server always applies its own configured
	// TempTokenTTL (authenticators.temp_token.ttl, default 15m). --ttl is
	// validated (so scripts get a clear error on garbage input) and then
	// surfaced as a warning rather than silently pretending it took effect.
	ttl := fs.String("ttl", "", "requested token TTL (e.g. 5m, 1h) — NOT currently enforced by the server; see the warning this prints")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *userID == "" {
		fmt.Fprintln(os.Stderr, progName+": --user is required")
		usage()
		return 2
	}
	if code := checkTTLFlag(*ttl); code != 0 {
		return code
	}

	client := apiclient.New(apiclient.WithNoRedirect())
	resp, err := client.Post("/api/v1/admin/tokens/temp", map[string]any{
		"user_id": *userID,
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
		fmt.Fprintln(os.Stderr, apiclient.StatusMessage(progName, "issue-temp", apiclient.RedirectHintAdmin, resp, body))
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
