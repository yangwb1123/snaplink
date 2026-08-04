package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/platform/buildinfo"
)

func TestModulesJSONReportsBillingFallbackInventory(t *testing.T) {
	oldProfile, oldDigest := buildinfo.BuildProfile, buildinfo.ModuleLockDigest
	oldModules, oldCapabilities := buildinfo.CompiledModules, buildinfo.CompiledCapabilities
	t.Cleanup(func() {
		buildinfo.BuildProfile, buildinfo.ModuleLockDigest = oldProfile, oldDigest
		buildinfo.CompiledModules, buildinfo.CompiledCapabilities = oldModules, oldCapabilities
	})
	buildinfo.BuildProfile, buildinfo.ModuleLockDigest = "standard", unlockedDigest

	var stdout, stderr bytes.Buffer
	handled, code := handleCommand([]string{"modules", "--json"}, &stdout, &stderr)
	if !handled || code != 0 || stderr.Len() != 0 {
		t.Fatalf("handled=%v code=%d stderr=%q", handled, code, stderr.String())
	}
	var inventory buildinfo.ModuleInventory
	if err := json.Unmarshal(stdout.Bytes(), &inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.Program != programName || inventory.Profile != billingProfile ||
		inventory.LockDigest != unlockedDigest || !slices.Equal(inventory.Modules, billingModules) ||
		!slices.Equal(inventory.Capabilities, billingCapabilities) {
		t.Fatalf("inventory = %+v", inventory)
	}
}

func TestVersionAndInvalidModulesCommands(t *testing.T) {
	oldVersion := version
	version = "v0.0.0-dev"
	t.Cleanup(func() { version = oldVersion })
	var stdout, stderr bytes.Buffer
	handled, code := handleCommand([]string{"version"}, &stdout, &stderr)
	if !handled || code != 0 || !strings.HasPrefix(stdout.String(), "snaplink-billing v0.0.0-dev\n") {
		t.Fatalf("handled=%v code=%d stdout=%q stderr=%q", handled, code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	handled, code = handleCommand([]string{"modules", "--yaml"}, &stdout, &stderr)
	if !handled || code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("handled=%v code=%d stdout=%q stderr=%q", handled, code, stdout.String(), stderr.String())
	}
}

func TestAuditSourceIDCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	handled, code := handleCommand([]string{
		"audit-source-id", "--tenant", "tenant-a", "--prefix", "billing",
	}, &stdout, &stderr)
	if !handled || code != 0 || stderr.Len() != 0 || !strings.HasPrefix(stdout.String(), "billing.") ||
		strings.Contains(stdout.String(), "tenant-a") {
		t.Fatalf("handled=%v code=%d stdout=%q stderr=%q", handled, code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	_, code = handleCommand([]string{"audit-source-id", "--tenant", " bad"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "invalid audit source") {
		t.Fatalf("invalid command code=%d stderr=%q", code, stderr.String())
	}
}
