package ssotest

import (
	"testing"

	"github.com/snaplink/sso/interfaces/sso"
)

func TestReadBuildInfo_CachesAndReturnsConsistently(t *testing.T) {
	first := sso.ReadBuildInfo()
	second := sso.ReadBuildInfo()
	if first != second {
		t.Fatalf("BuildInfo should be cached + identical across calls: first=%+v second=%+v", first, second)
	}
}

func TestReadBuildInfo_VersionAlwaysSet(t *testing.T) {
	// Under `go test` the Main.Version is empty; the helper
	// substitutes "(devel)". This contract matters for the health
	// endpoint — operators always see SOMETHING in the version
	// field rather than an empty string.
	bi := sso.ReadBuildInfo()
	if bi.Version == "" {
		t.Fatal("Version unexpectedly empty — helper should substitute '(devel)' / '(unknown)'")
	}
}
