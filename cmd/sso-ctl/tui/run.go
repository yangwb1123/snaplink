// Package tui implements an interactive terminal UI (bubbletea) for browsing
// and managing SSO admin entities over the same admin REST API the other
// sso-ctl subcommands (clientscmd, entitiescmd) use.
//
// Usage:
//
//	sso-ctl tui
//
// A top-level menu (Clients / Users / Tenants) pushes into a list view for
// the chosen entity, fetched from the admin API on entry. Within a list:
// "n" opens a create form, "e" edits the selected row, "d" asks for a y/n
// delete confirmation, "r" refreshes, "esc"/"q" goes back. Clients are
// read-only here (matching the existing read-only clientscmd) — n/e/d are
// no-ops that report so via the status line.
//
// Forms are a sequential set of text fields: tab/shift+tab move between
// them, enter on the last field (or ctrl+s from anywhere in the form)
// submits, esc cancels back to the list without saving. ctrl+c quits
// immediately from any screen.
package tui

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/snaplink/sso/cmd/sso-ctl/apiclient"
)

const progName = "sso-ctl tui"

// Run is the tui subcommand entry point. args is unused — the TUI takes no
// flags, apiclient.New() already reads SSO_ADMIN_ADDR / SSO_ADMIN_TOKEN from
// the environment. The signature matches every other sso-ctl subcommand so
// main.go can dispatch to it uniformly. Returns the process exit code.
func Run(args []string) int {
	client := apiclient.New()
	p := tea.NewProgram(newAppModel(client), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", progName, err)
		return 1
	}
	return 0
}
