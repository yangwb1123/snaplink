package core

import (
	"encoding/json"
	"testing"
)

func TestReadBuildInfo(t *testing.T) {
	t.Parallel()
	// Not parallel: ReadBuildInfo memoizes via sync.Once, and we assert the
	// same cached value is returned across calls.
	first := ReadBuildInfo()

	// Version is always populated to a non-empty marker: a real module
	// version, "(devel)" for untagged builds, or "(unknown)" when build
	// info is unavailable. The empty string is never a valid result.
	if first.Version == "" {
		t.Error("ReadBuildInfo().Version is empty; want a non-empty marker")
	}

	// The sync.Once cache must return the identical struct on every call.
	second := ReadBuildInfo()
	if first != second {
		t.Errorf("ReadBuildInfo not cached: %+v != %+v", first, second)
	}
}

func TestBuildInfoJSONOmitsEmptyVCS(t *testing.T) {
	t.Parallel()

	// VCSRevision / VCSTime are omitempty; a build without VCS data must not
	// emit the keys so operators can rely on their absence.
	b := BuildInfo{Version: "v1.2.3"}
	out, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	got := string(out)
	if got != `{"version":"v1.2.3"}` {
		t.Errorf("Marshal(no-vcs) = %s, want {\"version\":\"v1.2.3\"}", got)
	}

	// With VCS data populated, the optional keys appear.
	full := BuildInfo{Version: "v1.2.3", VCSRevision: "deadbeef", VCSTime: "2026-06-16T00:00:00Z"}
	out2, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("Marshal(full) error = %v", err)
	}
	var rt BuildInfo
	if err := json.Unmarshal(out2, &rt); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if rt != full {
		t.Errorf("BuildInfo round-trip = %+v, want %+v", rt, full)
	}
}
