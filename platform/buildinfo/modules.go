package buildinfo

import (
	"encoding/json"
	"io"
	"strings"
)

// BuildProfile, ModuleLockDigest, and CompiledModules are replaced by the
// profile builder through -ldflags. Defaults describe the normal repository
// build, which preserves the historical stock-server composition.
var (
	BuildProfile     = "standard"
	ModuleLockDigest = "unlocked"
	CompiledModules  = "core-runtime,stock-server"
)

// ModuleInventory is the non-secret build-time capability identity embedded in
// a configured binary. It intentionally contains no runtime configuration.
type ModuleInventory struct {
	Program    string   `json:"program"`
	Profile    string   `json:"profile"`
	LockDigest string   `json:"lock_digest"`
	Modules    []string `json:"modules"`
}

// Inventory returns a normalized snapshot of the configured build modules.
func Inventory(program string) ModuleInventory {
	parts := strings.Split(CompiledModules, ",")
	modules := make([]string, 0, len(parts))
	for _, part := range parts {
		if id := strings.TrimSpace(part); id != "" {
			modules = append(modules, id)
		}
	}
	return ModuleInventory{
		Program:    program,
		Profile:    fallback(BuildProfile, "unknown"),
		LockDigest: fallback(ModuleLockDigest, "unlocked"),
		Modules:    modules,
	}
}

// WriteModules renders the NGINX -V equivalent for a configured binary.
func WriteModules(w io.Writer, program string, asJSON bool) error {
	inventory := Inventory(program)
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(inventory)
	}
	if _, err := io.WriteString(w, inventory.Program+" modules\n"); err != nil {
		return err
	}
	if _, err := io.WriteString(w, "  profile: "+inventory.Profile+"\n"); err != nil {
		return err
	}
	if _, err := io.WriteString(w, "  lock:    "+inventory.LockDigest+"\n"); err != nil {
		return err
	}
	for _, id := range inventory.Modules {
		if _, err := io.WriteString(w, "  - "+id+"\n"); err != nil {
			return err
		}
	}
	return nil
}

func fallback(value, defaultValue string) string {
	if strings.TrimSpace(value) == "" {
		return defaultValue
	}
	return value
}
