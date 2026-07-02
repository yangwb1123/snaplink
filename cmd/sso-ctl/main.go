// Command sso-ctl is the offline operator toolbelt for the SSO server. It
// bundles the read-only / maintenance CLIs as subcommands so the project ships
// exactly two binaries — sso-server (the runtime) and sso-ctl (the toolbelt):
//
//	sso-ctl audit-verify ...   # verify the audit-log hash chain
//	sso-ctl audit-export ...   # export or offline-verify a tamper-evident bulk audit bundle
//	sso-ctl import ...         # bulk-import users (auth0 / keycloak / csv)
//	sso-ctl migrate ...        # offline schema-migration status
//	sso-ctl snapshot ...       # inspect / verify sealed state snapshots
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
	"github.com/snaplink/sso/cmd/sso-ctl/hashcmd"
	"github.com/snaplink/sso/cmd/sso-ctl/importcmd"
	"github.com/snaplink/sso/cmd/sso-ctl/migratecmd"
	"github.com/snaplink/sso/cmd/sso-ctl/sessionscmd"
	"github.com/snaplink/sso/cmd/sso-ctl/snapshotcmd"
	"github.com/snaplink/sso/cmd/sso-ctl/tokenscmd"
)

const progName = "sso-ctl"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "audit-verify":
		os.Exit(auditverify.Run(os.Args[2:]))
	case "audit-export":
		os.Exit(auditexport.Run(os.Args[2:]))
	case "clients":
		os.Exit(clientscmd.Run(os.Args[2:]))
	case "import":
		os.Exit(importcmd.Run(os.Args[2:]))
	case "migrate":
		os.Exit(migratecmd.Run(os.Args[2:]))
	case "sessions":
		os.Exit(sessionscmd.Run(os.Args[2:]))
	case "snapshot":
		os.Exit(snapshotcmd.Run(os.Args[2:]))
	case "config":
		os.Exit(configcmd.Run(os.Args[2:]))
	case "hash":
		os.Exit(hashcmd.Run(os.Args[2:]))
	case "tokens":
		os.Exit(tokenscmd.Run(os.Args[2:]))
	case "version", "-v", "--version":
		writeVersion(os.Stdout)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "%s: unknown subcommand %q\n", progName, os.Args[1])
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
  clients        List OAuth clients or inspect a specific client.
  import         Bulk-import users from auth0 / keycloak / csv into a user store.
  migrate        Offline schema-migration status for a SQLite store.
  sessions       List active sessions or revoke a specific session.
  snapshot       Inspect and verify sealed state snapshots.
  config         Validate a server config file offline (deploy pre-check).
  hash           Produce a server-compatible password hash (admin seeding).
  tokens         Revoke an access token or issue a temporary token.
  version        Print the toolbelt version and build revision.

Run "%s <command> -h" for command-specific flags.
`, progName, progName, progName)
}
