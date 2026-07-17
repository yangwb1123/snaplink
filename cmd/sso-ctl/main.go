// Command sso-ctl is the offline operator toolbelt for the SSO server. It
// bundles the read-only / maintenance CLIs as subcommands so the project ships
// exactly two binaries — sso-server (the runtime) and sso-ctl (the toolbelt):
//
//	sso-ctl audit-verify ...   # verify the audit-log hash chain
//	sso-ctl audit-export ...   # export or offline-verify a tamper-evident bulk audit bundle
//	sso-ctl soc2-report ...    # build a SOC2-flavored evidence pack over a verified audit-export bundle
//	sso-ctl import ...         # bulk-import users (auth0 / keycloak / csv)
//	sso-ctl migrate ...        # offline schema-migration status
//	sso-ctl snapshot ...       # inspect / verify sealed state snapshots
//	sso-ctl generate ...       # scaffold a new authenticator / store / handler / grant
//
// Each subcommand's process exit code is whatever its Run returns (or a direct
// os.Exit from a flag/usage error), byte-identical to the former standalone
// sso-audit-verify / sso-import / sso-migrate / sso-snapshotctl binaries.
package main

import (
	"fmt"
	"os"

	"github.com/snaplink/sso/cmd/sso-ctl/auditexport"
	"github.com/snaplink/sso/cmd/sso-ctl/auditverify"
	"github.com/snaplink/sso/cmd/sso-ctl/clientscmd"
	"github.com/snaplink/sso/cmd/sso-ctl/configcmd"
	"github.com/snaplink/sso/cmd/sso-ctl/generate"
	"github.com/snaplink/sso/cmd/sso-ctl/hashcmd"
	"github.com/snaplink/sso/cmd/sso-ctl/importcmd"
	"github.com/snaplink/sso/cmd/sso-ctl/migratecmd"
	"github.com/snaplink/sso/cmd/sso-ctl/sessionscmd"
	"github.com/snaplink/sso/cmd/sso-ctl/snapshotcmd"
	"github.com/snaplink/sso/cmd/sso-ctl/soc2report"
	"github.com/snaplink/sso/cmd/sso-ctl/tokenscmd"
)

const progName = "sso-ctl"

// subcommands maps each dispatchable tool name to its Run function. A
// map-based dispatch keeps main's cyclomatic complexity flat as tools are
// added — a growing switch statement here was the near-budget shape this
// table replaces (see AGENTS.md's function-complexity gate): adding a new
// sso-ctl subcommand now costs one map entry, not one more branch in main.
var subcommands = map[string]func([]string) int{
	"audit-verify": auditverify.Run,
	"audit-export": auditexport.Run,
	"soc2-report":  soc2report.Run,
	"clients":      clientscmd.Run,
	"import":       importcmd.Run,
	"migrate":      migratecmd.Run,
	"sessions":     sessionscmd.Run,
	"snapshot":     snapshotcmd.Run,
	"config":       configcmd.Run,
	"hash":         hashcmd.Run,
	"tokens":       tokenscmd.Run,
	"generate":     generate.Run,
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	if run, ok := subcommands[cmd]; ok {
		os.Exit(run(args))
	}
	switch cmd {
	case "version", "-v", "--version":
		writeVersion(os.Stdout)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "%s: unknown subcommand %q\n", progName, cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `%s — offline operator toolbelt for the SSO server.

Usage:
  %s <command> [arguments]

Commands:
  audit-verify   Verify the audit-log hash chain (from a file or the live API).
  audit-export   Export or offline-verify a tamper-evident bulk audit bundle (compliance evidence).
  soc2-report    Build a SOC2-flavored evidence pack over a verified audit-export bundle.
  clients        List OAuth clients or inspect a specific client.
  import         Bulk-import users from auth0 / keycloak / csv into a user store.
  migrate        Offline schema-migration status for a SQLite store.
  sessions       List active sessions or revoke a specific session.
  snapshot       Inspect and verify sealed state snapshots.
  config         Validate a server config file offline (deploy pre-check).
  hash           Produce a server-compatible password hash (admin seeding).
  tokens         Revoke an access token or issue a temporary token.
  generate       Scaffold boilerplate for a new authenticator, store, handler, or grant.
  version        Print the toolbelt version and build revision.

Run "%s <command> -h" for command-specific flags.
`, progName, progName, progName)
}
