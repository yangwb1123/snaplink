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

	"github.com/snaplink/sso/cmd/sso-ctl/apiclient"
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

func runList(args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	format := fs.String("format", "json", "output format: json or table")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	client := apiclient.New()
	resp, err := client.Get("/api/v1/admin/clients")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: list failed: %v\n", progName, err)
		return 1
	}
	body, err := apiclient.ReadBody(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", progName, err)
		return 1
	}
	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "%s: list failed (HTTP %d): %s\n", progName, resp.StatusCode, string(body))
		return 1
	}

	var result struct {
		Clients []struct {
			ID          string `json:"id"`
			Name        string `json:"name,omitempty"`
			Secret      string `json:"secret,omitempty"`
			TenantID    string `json:"tenant_id,omitempty"`
			GrantTypes  string `json:"grant_types,omitempty"`
			RedirectURI string `json:"redirect_uris,omitempty"`
		} `json:"clients"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Fprintf(os.Stderr, "%s: parse response: %v\n", progName, err)
		return 1
	}

	switch *format {
	case "table":
		header := []string{"ID", "Name", "TenantID", "GrantTypes"}
		rows := make([][]string, 0, len(result.Clients))
		for _, c := range result.Clients {
			rows = append(rows, []string{c.ID, c.Name, c.TenantID, c.GrantTypes})
		}
		apiclient.WriteTable(header, rows)
	default:
		apiclient.WriteJSON(result.Clients)
	}
	return 0
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
