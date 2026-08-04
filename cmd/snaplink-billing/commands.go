package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/yangwb1123/snaplink/infrastructure/auditgovernance"
	"github.com/yangwb1123/snaplink/platform/buildinfo"
)

const (
	billingProfile = "billing"
	unlockedDigest = "unlocked"
)

var version = ""

var billingModules = []string{"core-runtime", "billing-runtime"}

var billingCapabilities = []string{
	"commerce.tenant.v1",
	"config.host.v1",
	"core.runtime.v1",
	"lifecycle.host.v1",
	"metering.usage.v1",
	"security.policy.v1",
	"server.billing.v1",
}

func handleCommand(args []string, stdout, stderr io.Writer) (bool, int) {
	if len(args) == 0 {
		return false, 0
	}
	switch args[0] {
	case "version", "-version", "--version", "-v":
		if len(args) != 1 {
			return commandUsageError(stderr, "version accepts no arguments")
		}
		buildinfo.Write(stdout, programName, version)
		return true, 0
	case "modules":
		return handleModulesCommand(args[1:], stdout, stderr)
	case "audit-source-id":
		return handleAuditSourceCommand(args[1:], stdout, stderr)
	default:
		return false, 0
	}
}

func handleAuditSourceCommand(args []string, stdout, stderr io.Writer) (bool, int) {
	flags := flag.NewFlagSet("audit-source-id", flag.ContinueOnError)
	flags.SetOutput(stderr)
	tenantID := flags.String("tenant", "", "tenant ID")
	prefix := flags.String("prefix", defaultAuditPrefix, "Audit Governance source prefix")
	if err := flags.Parse(args); err != nil {
		return true, 2
	}
	if flags.NArg() != 0 || *tenantID == "" {
		return commandUsageError(stderr, "usage: snaplink-billing audit-source-id --tenant <id> [--prefix <prefix>]")
	}
	sourceID, err := auditgovernance.TenantSourceID(*prefix, *tenantID)
	if err != nil {
		return commandUsageError(stderr, "invalid audit source prefix or tenant ID")
	}
	if _, err := fmt.Fprintln(stdout, sourceID); err != nil {
		fmt.Fprintf(stderr, "%s: write audit source ID: %v\n", programName, err)
		return true, 1
	}
	return true, 0
}

func handleModulesCommand(args []string, stdout, stderr io.Writer) (bool, int) {
	if len(args) > 1 || (len(args) == 1 && args[0] != "--json") {
		return commandUsageError(stderr, "usage: snaplink-billing modules [--json]")
	}
	if err := writeBillingModules(stdout, len(args) == 1); err != nil {
		fmt.Fprintf(stderr, "%s: write module inventory: %v\n", programName, err)
		return true, 1
	}
	return true, 0
}

func commandUsageError(stderr io.Writer, message string) (bool, int) {
	fmt.Fprintf(stderr, "%s: %s\n", programName, message)
	return true, 2
}

func billingInventory() buildinfo.ModuleInventory {
	inventory := buildinfo.Inventory(programName)
	if inventory.Profile != "standard" || inventory.LockDigest != unlockedDigest {
		return inventory
	}
	inventory.Program = programName
	inventory.Profile = billingProfile
	inventory.Modules = append([]string(nil), billingModules...)
	inventory.Capabilities = append([]string(nil), billingCapabilities...)
	return inventory
}

func writeBillingModules(writer io.Writer, asJSON bool) error {
	inventory := billingInventory()
	if asJSON {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(inventory)
	}
	if _, err := fmt.Fprintf(writer, "%s modules\n  profile: %s\n  lock:    %s\n",
		inventory.Program, inventory.Profile, inventory.LockDigest); err != nil {
		return err
	}
	for _, id := range inventory.Modules {
		if _, err := fmt.Fprintf(writer, "  - %s\n", id); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(writer, "  capabilities:"); err != nil {
		return err
	}
	for _, id := range inventory.Capabilities {
		if _, err := fmt.Fprintf(writer, "    - %s\n", id); err != nil {
			return err
		}
	}
	return nil
}
