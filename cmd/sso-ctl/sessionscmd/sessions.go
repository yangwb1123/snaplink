// Package sessionscmd implements sso-ctl session management subcommands.
//
// Usage:
//
//	sso-ctl sessions list [--user=<id>] [--format=json|table]
//	sso-ctl sessions revoke <session-id>
package sessionscmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/snaplink/sso/cmd/sso-ctl/apiclient"
)

const progName = "sso-ctl sessions"

// Run is the sessions subcommand entry point. args excludes the leading
// "sessions" token. Returns the process exit code.
func Run(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	switch args[0] {
	case "list":
		return runList(args[1:])
	case "revoke":
		return runRevoke(args[1:])
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
	fmt.Fprint(os.Stderr, progName+` — manage user sessions.

Usage:
  `+progName+` list [--user=<id>] [--format=json|table]
  `+progName+` revoke <session-id>

Subcommands:
  list     List active sessions (optionally filtered by user).
  revoke   Revoke a specific session (forces logout).

Flags:
  --user     Filter sessions by user ID (optional).
  --format   Output format: "json" (default) or "table".

Examples:
  `+progName+` list
  `+progName+` list --user=user123
  `+progName+` list --format=table --user=user123
  `+progName+` revoke sess_abc123
`)
}

func runList(args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	userID := fs.String("user", "", "filter by user ID")
	format := fs.String("format", "json", "output format: json or table")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	path := "/api/v1/admin/tokens/sessions"
	if *userID != "" {
		path += "?user_id=" + *userID
	}
	body, ok := fetchList(path)
	if !ok {
		return 1
	}

	var result struct {
		Sessions []struct {
			ID            string `json:"id"`
			UserID        string `json:"user_id"`
			CreatedAtUnix int64  `json:"created_at_unix"`
			ExpiresAtUnix int64  `json:"expires_at_unix"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Fprintf(os.Stderr, "%s: parse response: %v\n", progName, err)
		return 1
	}

	switch *format {
	case "table":
		header := []string{"ID", "UserID", "Created", "Expires"}
		rows := make([][]string, 0, len(result.Sessions))
		for _, s := range result.Sessions {
			rows = append(rows, []string{
				s.ID,
				s.UserID,
				unixOrNever(s.CreatedAtUnix),
				unixOrNever(s.ExpiresAtUnix),
			})
		}
		apiclient.WriteTable(header, rows)
	default:
		apiclient.WriteJSON(result.Sessions)
	}
	return 0
}

// fetchList GETs an admin list endpoint and returns the response body.
// ok=false means the error was already printed to stderr (exit 1), exactly
// as the ladder ran inline in runList.
func fetchList(path string) ([]byte, bool) {
	client := apiclient.New()
	resp, err := client.Get(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: list failed: %v\n", progName, err)
		return nil, false
	}
	body, err := apiclient.ReadBody(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", progName, err)
		return nil, false
	}
	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "%s: list failed (HTTP %d): %s\n", progName, resp.StatusCode, string(body))
		return nil, false
	}
	return body, true
}

func runRevoke(args []string) int {
	if len(args) < 1 || args[0] == "" {
		fmt.Fprintln(os.Stderr, progName+": session-id is required")
		usage()
		return 2
	}
	sessionID := args[0]

	client := apiclient.New()
	resp, err := client.Post("/api/v1/admin/tokens/revoke", map[string]string{
		"session_id": sessionID,
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
	fmt.Printf("session %q revoked\n", sessionID)
	return 0
}

func unixOrNever(ts int64) string {
	if ts == 0 {
		return "never"
	}
	return strconv.FormatInt(ts, 10)
}
