package composition

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/yangwb1123/snaplink/platform/buildinfo"
)

const (
	ProgramName      = "snaplink"
	inventoryProgram = "snaplink"
	UnlockedDigest   = "unlocked"
)

var version = ""

// HandleCommand serves the version/modules commands; returns handled and the
// process exit code.
func HandleCommand(args []string, stdout, stderr io.Writer, edition Edition) (bool, int) {
	if len(args) == 0 {
		return false, 0
	}
	switch args[0] {
	case "version", "-version", "--version", "-v":
		if len(args) != 1 {
			return commandUsageError(stderr, "version accepts no arguments")
		}
		buildinfo.WriteProfile(
			stdout,
			ProgramName,
			version,
			moduleInventory(edition).Profile,
		)
		return true, 0
	case "modules":
		return handleModulesCommand(args[1:], stdout, stderr, edition)
	default:
		return false, 0
	}
}

func handleModulesCommand(args []string, stdout, stderr io.Writer, edition Edition) (bool, int) {
	if len(args) > 1 || (len(args) == 1 && args[0] != "--json") {
		return commandUsageError(stderr, "usage: sso-minimal modules [--json]")
	}
	if err := writeModules(stdout, len(args) == 1, edition); err != nil {
		fmt.Fprintf(stderr, "%s: write module inventory: %v\n", ProgramName, err)
		return true, 1
	}
	return true, 0
}

func commandUsageError(stderr io.Writer, message string) (bool, int) {
	fmt.Fprintf(stderr, "%s: %s\n", ProgramName, message)
	return true, 2
}

func writeModules(w io.Writer, asJSON bool, edition Edition) error {
	inventory := moduleInventory(edition)
	if asJSON {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(inventory)
	}
	if _, err := fmt.Fprintf(w, "%s modules\n  profile: %s\n  lock:    %s\n",
		inventory.Program, inventory.Profile, inventory.LockDigest); err != nil {
		return err
	}
	for _, id := range inventory.Modules {
		if _, err := fmt.Fprintf(w, "  - %s\n", id); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w, "  capabilities:"); err != nil {
		return err
	}
	for _, id := range inventory.Capabilities {
		if _, err := fmt.Fprintf(w, "    - %s\n", id); err != nil {
			return err
		}
	}
	return nil
}

// ModuleInventory returns the build-time module/capability identity for the
// edition. A configured build reports the ldflags-embedded values; an
// unlocked (plain `go build`) build falls back to the edition's own module
// list so the prototype root never claims the minimal edition's modules.
func ModuleInventory(edition Edition) buildinfo.ModuleInventory {
	return moduleInventory(edition)
}

func moduleInventory(edition Edition) buildinfo.ModuleInventory {
	inventory := buildinfo.Inventory(inventoryProgram)
	if inventory.Profile == "standard" && inventory.LockDigest == UnlockedDigest {
		inventory.Program = buildinfo.ProgramName(inventory.Program, edition.Profile)
		inventory.Profile = edition.Profile
		inventory.Modules = append([]string(nil), edition.Modules...)
		inventory.Capabilities = append([]string(nil), edition.Capabilities...)
	}
	return inventory
}
