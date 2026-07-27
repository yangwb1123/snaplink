// Package clientscmd implements sso-ctl client management subcommands.
//
// Usage:
//
//	sso-ctl clients list [--format=json|table]
//	sso-ctl clients get <client-id>
package clientscmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/yangwb1123/snaplink/cmd/sso-ctl/apiclient"
)

const progName = "sso-ctl clients"

// Run is the clients subcommand entry point. args excludes the leading
// "clients" token. Returns the process exit code.
func Run(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	switch args[0] {
	case "list":
		return runList(args[1:])
	case "get":
		return runGet(args[1:])
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
	fmt.Fprint(os.Stderr, progName+` — manage OAuth clients.

Usage:
  `+progName+` list [--format=json|table]
  `+progName+` get <client-id>

Subcommands:
  list  List all registered OAuth clients.
  get   Get details of a specific client by ID.

Flags:
  --format   Output format: "json" (default) or "table".

Examples:
  `+progName+` list
  `+progName+` list --format=table
  `+progName+` get client_abc123
`)
}

// clientListItem mirrors one entry of the admin gRPC-gateway's
// ListClientsResponse.clients. Field names/types here MUST match the
// gateway's actual wire shape, not the .proto's snake_case field names: the
// gateway marshals with protojson defaults (camelCase, no UseProtoNames —
// see grpc-gateway's defaultMarshaler), so "redirect_uris" never matches and
// silently stays empty. There is also no tenant_id/grant_types field on the
// Client message at all (see proto/admin/v1/clients.proto) — the closest
// equivalent the server exposes is token_strategy.
type clientListItem struct {
	ID            string   `json:"id"`
	Name          string   `json:"name,omitempty"`
	Secret        string   `json:"secret,omitempty"`
	TokenStrategy string   `json:"tokenStrategy,omitempty"`
	RedirectURIs  []string `json:"redirectUris,omitempty"`
	AllowedScopes []string `json:"allowedScopes,omitempty"`
	Active        bool     `json:"active"`
}

func runList(args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	format := fs.String("format", "json", "output format: json or table")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	body, ok := fetchList("/api/v1/admin/clients")
	if !ok {
		return 1
	}

	var result struct {
		Clients []clientListItem `json:"clients"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Fprintf(os.Stderr, "%s: parse response: %v\n", progName, err)
		return 1
	}
	printClients(*format, result.Clients)
	return 0
}

// printClients renders the decoded client list in the requested format.
func printClients(format string, clients []clientListItem) {
	if format != "table" {
		apiclient.WriteJSON(clients)
		return
	}
	header := []string{"ID", "Name", "TokenStrategy", "RedirectURIs", "Active"}
	rows := make([][]string, 0, len(clients))
	for _, c := range clients {
		rows = append(rows, []string{
			c.ID, c.Name, c.TokenStrategy,
			strings.Join(c.RedirectURIs, ","),
			strconv.FormatBool(c.Active),
		})
	}
	apiclient.WriteTable(header, rows)
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

func runGet(args []string) int {
	if len(args) < 1 || args[0] == "" {
		fmt.Fprintln(os.Stderr, progName+": client-id is required")
		usage()
		return 2
	}
	clientID := args[0]

	client := apiclient.New()
	resp, err := client.Get("/api/v1/admin/clients/" + clientID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: get failed: %v\n", progName, err)
		return 1
	}
	body, err := apiclient.ReadBody(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", progName, err)
		return 1
	}
	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "%s: get failed (HTTP %d): %s\n", progName, resp.StatusCode, string(body))
		return 1
	}
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Fprintf(os.Stderr, "%s: parse response: %v\n", progName, err)
		return 1
	}
	// Extract the nested client object
	if clientObj, ok := result["client"]; ok {
		apiclient.WriteJSON(clientObj)
	} else {
		apiclient.WriteJSON(result)
	}
	return 0
}
