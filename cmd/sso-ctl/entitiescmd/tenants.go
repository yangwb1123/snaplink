// Package entitiescmd implements sso-ctl tenant and admin-user management
// subcommands against the admin REST API.
//
// Usage:
//
//	sso-ctl tenants list|get|create|update|delete|set-status ...
//	sso-ctl users   list|get|create|update|delete ...
package entitiescmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/yangwb1123/snaplink/cmd/sso-ctl/apiclient"
)

const tenantsProg = "sso-ctl tenants"

// Tenant mirrors the admin API's Tenant resource.
type Tenant struct {
	ID             string            `json:"id"`
	Slug           string            `json:"slug,omitempty"`
	Name           string            `json:"name,omitempty"`
	Status         string            `json:"status,omitempty"`
	Settings       map[string]string `json:"settings,omitempty"`
	HomeRegion     string            `json:"home_region,omitempty"`
	AllowedRegions []string          `json:"allowed_regions,omitempty"`
	EnforceWrites  bool              `json:"enforce_writes,omitempty"`
}

// RunTenants is the tenants subcommand entry point. args excludes the
// leading "tenants" token. Returns the process exit code.
func RunTenants(args []string) int {
	if len(args) < 1 {
		tenantsUsage()
		return 2
	}
	switch args[0] {
	case "list":
		return runTenantList(args[1:])
	case "get":
		return runTenantGet(args[1:])
	case "create":
		return runTenantCreate(args[1:])
	case "update":
		return runTenantUpdate(args[1:])
	case "delete":
		return runTenantDelete(args[1:])
	case "set-status":
		return runTenantSetStatus(args[1:])
	case "-h", "--help", "help":
		tenantsUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "%s: unknown subcommand %q\n", tenantsProg, args[0])
		tenantsUsage()
		return 2
	}
}

func tenantsUsage() {
	fmt.Fprint(os.Stderr, tenantsProg+` — manage tenants.

Usage:
  `+tenantsProg+` list [--format=json|table]
  `+tenantsProg+` get <tenant-id>
  `+tenantsProg+` create --id=<id> --status=<active|suspended> [--slug=<slug>] [--name=<name>]
  `+tenantsProg+` update <tenant-id> [--slug=<slug>] [--name=<name>]
  `+tenantsProg+` delete <tenant-id> --yes
  `+tenantsProg+` set-status <tenant-id> <active|suspended>

Subcommands:
  list        List all tenants.
  get         Get details of a specific tenant by ID.
  create      Create a new tenant.
  update      Update a tenant's slug/name. Status is NOT settable here — use set-status.
  delete      Delete a tenant (requires --yes to confirm).
  set-status  Activate or suspend a tenant.

Flags:
  --format   Output format for list/get: "json" (default) or "table".
  --id       Tenant ID (create, required).
  --slug     Tenant slug (create/update).
  --name     Tenant name (create/update).
  --status   Tenant status: "active" or "suspended" (create, required).
  --yes      Confirm deletion (delete, required).

Examples:
  `+tenantsProg+` list --format=table
  `+tenantsProg+` get tenant_abc123
  `+tenantsProg+` create --id=acme --status=active --name="Acme Inc"
  `+tenantsProg+` update acme --name="Acme Incorporated"
  `+tenantsProg+` delete acme --yes
  `+tenantsProg+` set-status acme suspended
`)
}

func runTenantList(args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	format := fs.String("format", "json", "output format: json or table")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	body, ok := fetchList(tenantsProg, "/api/v1/admin/tenants")
	if !ok {
		return 1
	}

	var result struct {
		Tenants []Tenant `json:"tenants"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Fprintf(os.Stderr, "%s: parse response: %v\n", tenantsProg, err)
		return 1
	}

	switch *format {
	case "table":
		header := []string{"ID", "Name", "Slug", "Status"}
		rows := make([][]string, 0, len(result.Tenants))
		for _, t := range result.Tenants {
			rows = append(rows, []string{t.ID, t.Name, t.Slug, t.Status})
		}
		apiclient.WriteTable(header, rows)
	default:
		apiclient.WriteJSON(result.Tenants)
	}
	return 0
}

func runTenantGet(args []string) int {
	if len(args) < 1 || args[0] == "" {
		fmt.Fprintln(os.Stderr, tenantsProg+": tenant-id is required")
		tenantsUsage()
		return 2
	}
	body, ok := fetchOne(tenantsProg, "/api/v1/admin/tenants/"+args[0])
	if !ok {
		return 1
	}
	return printEntity(tenantsProg, body, "tenant")
}

func runTenantCreate(args []string) int {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	id := fs.String("id", "", "tenant ID (required)")
	slug := fs.String("slug", "", "tenant slug")
	name := fs.String("name", "", "tenant name")
	status := fs.String("status", "", "tenant status: active or suspended (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *id == "" {
		fmt.Fprintln(os.Stderr, tenantsProg+": --id is required")
		return 2
	}
	if err := validateTenantStatus(*status); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", tenantsProg, err)
		return 2
	}

	t := Tenant{ID: *id, Slug: *slug, Name: *name, Status: *status}
	body, ok := doWrite(tenantsProg, http.MethodPost, "/api/v1/admin/tenants", t, "create")
	if !ok {
		return 1
	}
	return printEntity(tenantsProg, body, "tenant")
}

func runTenantUpdate(args []string) int {
	if len(args) < 1 || args[0] == "" {
		fmt.Fprintln(os.Stderr, tenantsProg+": tenant-id is required")
		tenantsUsage()
		return 2
	}
	id := args[0]
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	slug := fs.String("slug", "", "tenant slug")
	name := fs.String("name", "", "tenant name")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	// status is deliberately omitted: the server ignores/preserves status on
	// PUT, and status transitions must go through set-status instead.
	reqBody := map[string]string{"id": id, "slug": *slug, "name": *name}
	body, ok := doWrite(tenantsProg, http.MethodPut, "/api/v1/admin/tenants/"+id, reqBody, "update")
	if !ok {
		return 1
	}
	return printEntity(tenantsProg, body, "tenant")
}

func runTenantDelete(args []string) int {
	if len(args) < 1 || args[0] == "" {
		fmt.Fprintln(os.Stderr, tenantsProg+": tenant-id is required")
		tenantsUsage()
		return 2
	}
	id := args[0]
	fs := flag.NewFlagSet("delete", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "confirm deletion (required)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if !*yes {
		fmt.Fprintf(os.Stderr, "%s: this will permanently delete tenant %q\n", tenantsProg, id)
		fmt.Fprintf(os.Stderr, "%s: refusing without --yes; re-run: %s delete %s --yes\n", tenantsProg, tenantsProg, id)
		return 2
	}

	if _, ok := doWrite(tenantsProg, http.MethodDelete, "/api/v1/admin/tenants/"+id, nil, "delete"); !ok {
		return 1
	}
	fmt.Printf("tenant %q deleted\n", id)
	return 0
}

func runTenantSetStatus(args []string) int {
	if len(args) < 2 || args[0] == "" || args[1] == "" {
		fmt.Fprintln(os.Stderr, tenantsProg+": usage: set-status <tenant-id> <active|suspended>")
		tenantsUsage()
		return 2
	}
	id, status := args[0], args[1]
	if err := validateTenantStatus(status); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", tenantsProg, err)
		return 2
	}

	body, ok := doWrite(tenantsProg, http.MethodPost, "/api/v1/admin/tenants/"+id+":set-status",
		map[string]string{"status": status}, "set-status")
	if !ok {
		return 1
	}
	return printEntity(tenantsProg, body, "tenant")
}

func validateTenantStatus(status string) error {
	if status != "active" && status != "suspended" {
		return fmt.Errorf("--status must be %q or %q, got %q", "active", "suspended", status)
	}
	return nil
}

// fetchList GETs an admin list endpoint and returns the response body.
// ok=false means the error was already printed to stderr (exit 1). Shared
// by tenants.go and users.go — same pattern, only the path differs.
func fetchList(progName, path string) ([]byte, bool) {
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

// fetchOne GETs a single admin resource and returns the response body.
// ok=false means the error was already printed to stderr (exit 1).
func fetchOne(progName, path string) ([]byte, bool) {
	client := apiclient.New()
	resp, err := client.Get(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: get failed: %v\n", progName, err)
		return nil, false
	}
	body, err := apiclient.ReadBody(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", progName, err)
		return nil, false
	}
	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "%s: get failed (HTTP %d): %s\n", progName, resp.StatusCode, string(body))
		return nil, false
	}
	return body, true
}

// doWrite performs an authenticated write (POST/PUT/DELETE) and returns the
// decoded response body. verb labels the action in error output (e.g.
// "create", "update", "delete", "set-status"). ok=false means the error was
// already printed to stderr (exit 1).
func doWrite(progName, method, path string, reqBody any, verb string) ([]byte, bool) {
	client := apiclient.New()
	resp, err := client.Do(method, path, reqBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s failed: %v\n", progName, verb, err)
		return nil, false
	}
	body, err := apiclient.ReadBody(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", progName, err)
		return nil, false
	}
	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "%s: %s failed (HTTP %d): %s\n", progName, verb, resp.StatusCode, string(body))
		return nil, false
	}
	return body, true
}

// printEntity unmarshals body and prints the nested `key` object if present
// (the admin API wraps single-resource responses, e.g. {"tenant": {...}}),
// falling back to the raw decoded body otherwise. Returns the process exit
// code (0, or 1 on a parse failure).
func printEntity(progName string, body []byte, key string) int {
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Fprintf(os.Stderr, "%s: parse response: %v\n", progName, err)
		return 1
	}
	if obj, ok := result[key]; ok {
		apiclient.WriteJSON(obj)
	} else {
		apiclient.WriteJSON(result)
	}
	return 0
}
