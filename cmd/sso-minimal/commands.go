package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/snaplink/sso/platform/buildinfo"
)

const (
	programName      = "sso-minimal"
	inventoryProgram = "sso-server"
	prototypeProfile = "sso-prototype"
	prototypeLock    = "unlocked"
)

var version = ""

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
	default:
		return false, 0
	}
}

func handleModulesCommand(args []string, stdout, stderr io.Writer) (bool, int) {
	if len(args) > 1 || (len(args) == 1 && args[0] != "--json") {
		return commandUsageError(stderr, "usage: sso-minimal modules [--json]")
	}
	if err := writeModules(stdout, len(args) == 1); err != nil {
		fmt.Fprintf(stderr, "%s: write module inventory: %v\n", programName, err)
		return true, 1
	}
	return true, 0
}

func commandUsageError(stderr io.Writer, message string) (bool, int) {
	fmt.Fprintf(stderr, "%s: %s\n", programName, message)
	return true, 2
}

func writeModules(w io.Writer, asJSON bool) error {
	inventory := moduleInventory()
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
	return nil
}

func moduleInventory() buildinfo.ModuleInventory {
	inventory := buildinfo.Inventory(inventoryProgram)
	if inventory.Profile == "standard" && inventory.LockDigest == prototypeLock {
		inventory.Profile = prototypeProfile
		inventory.Modules = []string{"core-runtime", "sso-prototype-runtime"}
	}
	return inventory
}
