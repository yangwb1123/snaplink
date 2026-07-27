package buildinfo

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestInventoryNormalizesModuleList(t *testing.T) {
	oldProfile, oldDigest, oldModules := BuildProfile, ModuleLockDigest, CompiledModules
	t.Cleanup(func() {
		BuildProfile, ModuleLockDigest, CompiledModules = oldProfile, oldDigest, oldModules
	})
	BuildProfile = "minimal"
	ModuleLockDigest = "sha256:abc"
	CompiledModules = "core-runtime, oauth-client-credentials, "

	got := Inventory("demo")
	if got.Program != "demo" || got.Profile != "minimal" || got.LockDigest != "sha256:abc" {
		t.Fatalf("Inventory metadata = %+v", got)
	}
	if strings.Join(got.Modules, ",") != "core-runtime,oauth-client-credentials" {
		t.Fatalf("Inventory modules = %v", got.Modules)
	}
}

func TestWriteModulesJSON(t *testing.T) {
	var out strings.Builder
	if err := WriteModules(&out, "demo", true); err != nil {
		t.Fatalf("WriteModules: %v", err)
	}
	var got ModuleInventory
	if err := json.Unmarshal([]byte(out.String()), &got); err != nil {
		t.Fatalf("JSON output: %v", err)
	}
	if got.Program != "demo" || len(got.Modules) == 0 {
		t.Fatalf("decoded inventory = %+v", got)
	}
}

func TestWriteModulesText(t *testing.T) {
	var out strings.Builder
	if err := WriteModules(&out, "demo", false); err != nil {
		t.Fatalf("WriteModules: %v", err)
	}
	for _, want := range []string{"demo modules", "profile:", "lock:", "core-runtime"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("text output %q missing %q", out.String(), want)
		}
	}
}
