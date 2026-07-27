package entitiescmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yangwb1123/snaplink/cmd/sso-ctl/apiclient"
)

const usersProg = "sso-ctl users"

// AdminUser mirrors the admin API's AdminUser resource.
type AdminUser struct {
	ID         string            `json:"id"`
	ExternalID string            `json:"external_id,omitempty"`
	Provider   string            `json:"provider,omitempty"`
	Attributes map[string]string `json:"attributes"`
}

// attrFlag implements flag.Value, collecting repeatable --attr=key=value
// pairs into a map. A malformed pair (missing "=") is rejected at parse
// time so a typo fails fast instead of silently dropping an attribute.
type attrFlag map[string]string

func (a attrFlag) String() string {
	if len(a) == 0 {
		return ""
	}
	parts := make([]string, 0, len(a))
	for k, v := range a {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ",")
}

func (a attrFlag) Set(s string) error {
	key, value, ok := strings.Cut(s, "=")
	if !ok || key == "" {
		return fmt.Errorf("invalid --attr %q, want key=value", s)
	}
	a[key] = value
	return nil
}

// RunUsers is the users subcommand entry point. args excludes the leading
// "users" token. Returns the process exit code.
func RunUsers(args []string) int {
	if len(args) < 1 {
		usersUsage()
		return 2
	}
	switch args[0] {
	case "list":
		return runUserList(args[1:])
	case "get":
		return runUserGet(args[1:])
	case "create":
		return runUserCreate(args[1:])
	case "update":
		return runUserUpdate(args[1:])
	case "delete":
		return runUserDelete(args[1:])
	case "-h", "--help", "help":
		usersUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "%s: unknown subcommand %q\n", usersProg, args[0])
		usersUsage()
		return 2
	}
}

func usersUsage() {
	fmt.Fprint(os.Stderr, usersProg+` — manage admin users.

Usage:
  `+usersProg+` list [--format=json|table]
  `+usersProg+` get <user-id>
  `+usersProg+` create --id=<id> [--external-id=<id>] [--provider=<name>] [--attr=key=value ...]
  `+usersProg+` update <user-id> [--external-id=<id>] [--provider=<name>] [--attr=key=value ...]
  `+usersProg+` delete <user-id> --yes

Subcommands:
  list    List all admin users.
  get     Get details of a specific user by ID.
  create  Create a new admin user.
  update  Update an existing admin user.
  delete  Delete an admin user (requires --yes to confirm).

Flags:
  --format       Output format for list/get: "json" (default) or "table".
  --id           User ID (create, required).
  --external-id  External identity provider's user ID (create/update).
  --provider     Identity provider name (create/update).
  --attr         Attribute key=value; repeatable (create/update).
  --yes          Confirm deletion (delete, required).

Examples:
  `+usersProg+` list --format=table
  `+usersProg+` get user_abc123
  `+usersProg+` create --id=u1 --external-id=abc --provider=auth0 --attr=email=a@example.com
  `+usersProg+` update u1 --attr=email=new@example.com
  `+usersProg+` delete u1 --yes
`)
}

func runUserList(args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	format := fs.String("format", "json", "output format: json or table")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	body, ok := fetchList(usersProg, "/api/v1/admin/users")
	if !ok {
		return 1
	}

	var result struct {
		Users []AdminUser `json:"users"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Fprintf(os.Stderr, "%s: parse response: %v\n", usersProg, err)
		return 1
	}

	switch *format {
	case "table":
		header := []string{"ID", "ExternalID", "Provider"}
		rows := make([][]string, 0, len(result.Users))
		for _, u := range result.Users {
			rows = append(rows, []string{u.ID, u.ExternalID, u.Provider})
		}
		apiclient.WriteTable(header, rows)
	default:
		apiclient.WriteJSON(result.Users)
	}
	return 0
}

func runUserGet(args []string) int {
	if len(args) < 1 || args[0] == "" {
		fmt.Fprintln(os.Stderr, usersProg+": user-id is required")
		usersUsage()
		return 2
	}
	body, ok := fetchOne(usersProg, "/api/v1/admin/users/"+args[0])
	if !ok {
		return 1
	}
	return printEntity(usersProg, body, "user")
}

func runUserCreate(args []string) int {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	id := fs.String("id", "", "user ID (required)")
	extID := fs.String("external-id", "", "external identity provider's user ID")
	provider := fs.String("provider", "", "identity provider name")
	attrs := attrFlag{}
	fs.Var(attrs, "attr", "attribute key=value (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *id == "" {
		fmt.Fprintln(os.Stderr, usersProg+": --id is required")
		return 2
	}

	u := AdminUser{ID: *id, ExternalID: *extID, Provider: *provider, Attributes: attrs}
	body, ok := doWrite(usersProg, http.MethodPost, "/api/v1/admin/users", u, "create")
	if !ok {
		return 1
	}
	return printEntity(usersProg, body, "user")
}

func runUserUpdate(args []string) int {
	if len(args) < 1 || args[0] == "" {
		fmt.Fprintln(os.Stderr, usersProg+": user-id is required")
		usersUsage()
		return 2
	}
	id := args[0]
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	extID := fs.String("external-id", "", "external identity provider's user ID")
	provider := fs.String("provider", "", "identity provider name")
	attrs := attrFlag{}
	fs.Var(attrs, "attr", "attribute key=value (repeatable)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	u := AdminUser{ID: id, ExternalID: *extID, Provider: *provider, Attributes: attrs}
	body, ok := doWrite(usersProg, http.MethodPut, "/api/v1/admin/users/"+id, u, "update")
	if !ok {
		return 1
	}
	return printEntity(usersProg, body, "user")
}

func runUserDelete(args []string) int {
	if len(args) < 1 || args[0] == "" {
		fmt.Fprintln(os.Stderr, usersProg+": user-id is required")
		usersUsage()
		return 2
	}
	id := args[0]
	fs := flag.NewFlagSet("delete", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "confirm deletion (required)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if !*yes {
		fmt.Fprintf(os.Stderr, "%s: this will permanently delete user %q\n", usersProg, id)
		fmt.Fprintf(os.Stderr, "%s: refusing without --yes; re-run: %s delete %s --yes\n", usersProg, usersProg, id)
		return 2
	}

	if _, ok := doWrite(usersProg, http.MethodDelete, "/api/v1/admin/users/"+id, nil, "delete"); !ok {
		return 1
	}
	fmt.Printf("user %q deleted\n", id)
	return 0
}
