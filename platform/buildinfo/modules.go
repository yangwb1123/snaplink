package buildinfo

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// BuildProfile, ModuleLockDigest, CompiledModules, and CompiledCapabilities are
// replaced by the profile builder through -ldflags. Defaults describe the
// historical stock-server composition.
var (
	BuildProfile         = "standard"
	ModuleLockDigest     = "unlocked"
	CompiledModules      = "core-runtime,stock-server"
	CompiledCapabilities = "audit.host.v1,config.host.v1,core.runtime.v1,lifecycle.host.v1,security.policy.v1,server.stock.v1"
)

// ModuleInventory is the non-secret build-time capability identity embedded in
// a configured binary. It intentionally contains no runtime configuration.
type ModuleInventory struct {
	Program      string   `json:"program"`
	Profile      string   `json:"profile"`
	LockDigest   string   `json:"lock_digest"`
	Modules      []string `json:"modules"`
	Capabilities []string `json:"capabilities"`
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
		Program:      ProgramName(program, BuildProfile),
		Profile:      fallback(BuildProfile, "unknown"),
		LockDigest:   fallback(ModuleLockDigest, "unlocked"),
		Modules:      modules,
		Capabilities: normalizedCapabilities(CompiledCapabilities),
	}
}

func normalizedCapabilities(raw string) []string {
	seen := make(map[string]struct{})
	for _, part := range strings.Split(raw, ",") {
		if id := strings.TrimSpace(part); id != "" {
			seen[id] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// ValidateRequiredCapabilities fails when configuration requires a capability
// the immutable build profile did not compile.
func ValidateRequiredCapabilities(required []string) error {
	compiled := make(map[string]struct{})
	for _, id := range normalizedCapabilities(CompiledCapabilities) {
		compiled[id] = struct{}{}
	}
	var missing []string
	for _, id := range required {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := compiled[id]; !ok {
			missing = append(missing, id)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf("build profile %q lacks required capabilities: %s",
		fallback(BuildProfile, "unknown"), strings.Join(missing, ", "))
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
	if _, err := io.WriteString(w, "  capabilities:\n"); err != nil {
		return err
	}
	for _, id := range inventory.Capabilities {
		if _, err := io.WriteString(w, "    - "+id+"\n"); err != nil {
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
