package buildinfo

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestInventoryNormalizesModuleList(t *testing.T) {
	oldProfile, oldDigest := BuildProfile, ModuleLockDigest
	oldModules, oldCapabilities := CompiledModules, CompiledCapabilities
	t.Cleanup(func() {
		BuildProfile, ModuleLockDigest = oldProfile, oldDigest
		CompiledModules, CompiledCapabilities = oldModules, oldCapabilities
	})
	BuildProfile = "minimal"
	ModuleLockDigest = "sha256:abc"
	CompiledModules = "core-runtime, oauth-client-credentials, "
	CompiledCapabilities = "z.v1, a.v1, z.v1"

	got := Inventory("demo")
	if got.Program != "snaplink" || got.Profile != "minimal" || got.LockDigest != "sha256:abc" {
		t.Fatalf("Inventory metadata = %+v", got)
	}
	if strings.Join(got.Modules, ",") != "core-runtime,oauth-client-credentials" {
		t.Fatalf("Inventory modules = %v", got.Modules)
	}
	if strings.Join(got.Capabilities, ",") != "a.v1,z.v1" {
		t.Fatalf("Inventory capabilities = %v", got.Capabilities)
	}
}

func TestValidateRequiredCapabilities(t *testing.T) {
	oldProfile, oldCapabilities := BuildProfile, CompiledCapabilities
	t.Cleanup(func() {
		BuildProfile, CompiledCapabilities = oldProfile, oldCapabilities
	})
	BuildProfile = "minimal"
	CompiledCapabilities = "core.runtime.v1, oidc.common.v1"
	if err := ValidateRequiredCapabilities([]string{" oidc.common.v1 "}); err != nil {
		t.Fatalf("compiled requirement rejected: %v", err)
	}
	err := ValidateRequiredCapabilities([]string{"admin.control-plane.v1"})
	if err == nil || !strings.Contains(err.Error(), "admin.control-plane.v1") {
		t.Fatalf("missing requirement error = %v", err)
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
	for _, want := range []string{"demo modules", "profile:", "lock:", "core-runtime", "capabilities:"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("text output %q missing %q", out.String(), want)
		}
	}
}
