package controller

import (
	"strings"
	"testing"
)

// TestValidatePatch_RejectsUnknownOps pins acceptance (a) op-set rule:
// anything outside the server's documented {add, remove, replace} emit
// set (platform/configaudit diff.go:27) is an error. The message names
// the op index and a STATIC reason and never echoes the offending op
// string (F1 disposition: no response-derived bytes in Status.Message).
func TestValidatePatch_RejectsUnknownOps(t *testing.T) {
	snapshot := map[string]interface{}{"issuer": "https://a.example"}
	for _, op := range []string{"move", "copy", "test", "", "unknown"} {
		err := validatePatch([]patchOp{{Op: op, Path: "/issuer"}}, snapshot)
		if err == nil {
			t.Errorf("op %q: validatePatch = nil, want error", op)
			continue
		}
		if !strings.Contains(err.Error(), "op[0]: unsupported operation") {
			t.Errorf("op %q: error %q does not name the op index and static reason", op, err)
		}
		if op != "" && strings.Contains(err.Error(), op) {
			t.Errorf("op %q: error %q echoes the offending op string", op, err)
		}
	}
}

// TestValidatePatch_RejectsUnresolvablePaths pins acceptance (a)
// resolution rule: remove/replace need the leaf key to exist in the
// snapshot, add needs its parent to resolve to an object.
func TestValidatePatch_RejectsUnresolvablePaths(t *testing.T) {
	snapshot := map[string]interface{}{"issuer": "https://a.example"}
	tests := []struct {
		name string
		op   patchOp
		want string
	}{
		{"remove missing leaf", patchOp{Op: "remove", Path: "/nonexistent"}, "remove path does not resolve into the snapshot"},
		{"replace missing leaf", patchOp{Op: "replace", Path: "/nonexistent"}, "replace path does not resolve into the snapshot"},
		{"add under missing parent", patchOp{Op: "add", Path: "/no_such_parent/x"}, "add parent does not resolve into the snapshot"},
	}
	for _, tt := range tests {
		err := validatePatch([]patchOp{tt.op}, snapshot)
		if err == nil {
			t.Errorf("%s: validatePatch = nil, want error", tt.name)
			continue
		}
		if !strings.Contains(err.Error(), "op[0]: "+tt.want) {
			t.Errorf("%s: error %q, want reason %q", tt.name, err, tt.want)
		}
	}
}

// TestValidatePatch_RejectsInvalidPaths pins acceptance (a) path-shape
// rule: paths must be /-rooted, strictly RFC 6901-escaped, and every
// intermediate must be an object (the server recurses only into objects,
// never into arrays or through scalars).
func TestValidatePatch_RejectsInvalidPaths(t *testing.T) {
	snapshot := map[string]interface{}{
		"issuer":  "x",
		"clients": []interface{}{map[string]interface{}{"name": "c"}},
	}
	tests := []struct {
		name string
		path string
	}{
		{"no leading slash", "issuer"},
		{"empty path", ""},
		{"invalid escape ~2", "/iss~2uer"},
		{"scalar intermediate", "/issuer/nested"},
		{"array intermediate", "/clients/0/name"},
	}
	for _, tt := range tests {
		err := validatePatch([]patchOp{{Op: "replace", Path: tt.path}}, snapshot)
		if err == nil {
			t.Errorf("%s: validatePatch = nil, want error", tt.name)
		}
	}
}

// TestValidatePatch_AcceptsServerLegitimate pins acceptance (c): the
// documented emit set passes unchanged, including nested object paths,
// array-valued replace at a resolvable path, and remove on an existing
// key. Fixtures are the exact bodies the server's Diff produces.
func TestValidatePatch_AcceptsServerLegitimate(t *testing.T) {
	tests := []struct {
		name     string
		snapshot map[string]interface{}
		patch    []patchOp
	}{
		{
			"TestReconcile_DriftDetected fixture",
			map[string]interface{}{"issuer": "https://a.example"},
			[]patchOp{
				{Op: "replace", Path: "/issuer", Value: "https://b.example"},
				{Op: "add", Path: "/new_field", Value: true},
			},
		},
		{
			"nested object paths",
			map[string]interface{}{
				"clients": map[string]interface{}{
					"c1": map[string]interface{}{"redirect_uris": []interface{}{"u0"}},
				},
				"old_key": 1,
			},
			[]patchOp{
				{Op: "replace", Path: "/clients/c1/redirect_uris", Value: []interface{}{"u1"}},
				{Op: "remove", Path: "/old_key"},
			},
		},
	}
	for _, tt := range tests {
		if err := validatePatch(tt.patch, tt.snapshot); err != nil {
			t.Errorf("%s: validatePatch = %v, want nil", tt.name, err)
		}
	}
}

// TestValidatePatch_AcceptsEmptyPatch pins acceptance (c) regression: an
// empty patch is exactly how "no drift" is truthfully reported today
// (TestReconcile_NoDrift depends on it).
func TestValidatePatch_AcceptsEmptyPatch(t *testing.T) {
	snapshot := map[string]interface{}{"issuer": "https://a.example"}
	if err := validatePatch(nil, snapshot); err != nil {
		t.Errorf("nil patch: validatePatch = %v, want nil", err)
	}
	if err := validatePatch([]patchOp{}, snapshot); err != nil {
		t.Errorf("empty patch: validatePatch = %v, want nil", err)
	}
}

// TestValidateRunningSnapshot pins acceptance (b): the server itself
// answers 400 to len(snapshot)==0 (handlers.go:105), so an empty running
// snapshot is unverifiable and must fail the check.
func TestValidateRunningSnapshot(t *testing.T) {
	if err := validateRunningSnapshot(map[string]interface{}{}); err == nil {
		t.Error("validateRunningSnapshot({}) = nil, want error")
	}
	if err := validateRunningSnapshot(map[string]interface{}{"issuer": "x"}); err != nil {
		t.Errorf("validateRunningSnapshot(non-empty) = %v, want nil", err)
	}
}

// TestValidatePatch_EmptyKeyPath pins design decision D-A: the server
// emits the path "/" for a snapshot holding the empty-string key
// (diff.go:57-58 childPath = path + "/" + key with path ""), so "/" must
// resolve by key lookup rather than being rejected as a short path.
func TestValidatePatch_EmptyKeyPath(t *testing.T) {
	snapshot := map[string]interface{}{"": "empty-key-value"}
	if err := validatePatch([]patchOp{{Op: "replace", Path: "/"}}, snapshot); err != nil {
		t.Errorf("replace / against empty-key snapshot: %v, want nil", err)
	}
	if err := validatePatch([]patchOp{{Op: "add", Path: "/"}}, snapshot); err != nil {
		t.Errorf("add / against empty-key snapshot: %v, want nil", err)
	}
	if err := validatePatch([]patchOp{{Op: "remove", Path: "/"}}, map[string]interface{}{"issuer": "x"}); err == nil {
		t.Error("remove / against snapshot without empty key: nil, want error")
	}
}

// TestValidatePatch_EscapedKeyRoundTrip pins D-A/D-B: keys containing
// "/" and "~" resolve via their ~1/~0 escapes, and strict unescaping
// rejects shapes the server's escapePointerSegment can never produce
// (~2, trailing ~) while decoding ~01 correctly to ~1.
func TestValidatePatch_EscapedKeyRoundTrip(t *testing.T) {
	snapshot := map[string]interface{}{
		"a/b": 1,
		"a~b": 2,
	}
	if err := validatePatch([]patchOp{{Op: "replace", Path: "/a~1b"}}, snapshot); err != nil {
		t.Errorf("replace /a~1b: %v, want nil", err)
	}
	if err := validatePatch([]patchOp{{Op: "replace", Path: "/a~0b"}}, snapshot); err != nil {
		t.Errorf("replace /a~0b: %v, want nil", err)
	}
	// "/a~01b" unescapes to key "a~1b" (tilde escape then literal 1) —
	// the strict scanner's interpretation, and not a snapshot key here.
	if err := validatePatch([]patchOp{{Op: "replace", Path: "/a~01b"}}, snapshot); err == nil {
		t.Error("replace /a~01b: nil, want error (no such key after strict unescape)")
	}
	for _, path := range []string{"/iss~2uer", "/trailing~"} {
		if err := validatePatch([]patchOp{{Op: "replace", Path: path}}, snapshot); err == nil {
			t.Errorf("replace %s: nil, want error", path)
		}
	}
}

// TestValidatePatch_DashSegmentIsObjectKey pins D-B: "-" is an ordinary
// object key to this resolver — RFC 6901's "-" special case is defined
// only for arrays, which the server never traverses (diffMaps recurses
// only into objects).
func TestValidatePatch_DashSegmentIsObjectKey(t *testing.T) {
	snapshot := map[string]interface{}{"-": "dash-key"}
	if err := validatePatch([]patchOp{{Op: "replace", Path: "/-"}}, snapshot); err != nil {
		t.Errorf("replace /-: %v, want nil", err)
	}
}

// TestValidatePatch_NullValuedLeaf pins D-C: existence is key presence,
// never value shape — a null-valued leaf is a legitimate replace target.
func TestValidatePatch_NullValuedLeaf(t *testing.T) {
	snapshot := map[string]interface{}{"issuer": nil}
	if err := validatePatch([]patchOp{{Op: "replace", Path: "/issuer"}}, snapshot); err != nil {
		t.Errorf("replace /issuer on null leaf: %v, want nil", err)
	}
}

// TestValidatePatch_MapValuedLeafReplace pins D-C: a replace at a
// map-valued path is genuinely emittable (the server emits whole-value
// replace on type change, diff.go:71-82), so leaf maps must pass.
func TestValidatePatch_MapValuedLeafReplace(t *testing.T) {
	snapshot := map[string]interface{}{"obj": map[string]interface{}{"k": 1}}
	if err := validatePatch([]patchOp{{Op: "replace", Path: "/obj"}}, snapshot); err != nil {
		t.Errorf("replace /obj on map leaf: %v, want nil", err)
	}
}

// TestValidatePatch_AdversarialPaths pins FM3: hostile path strings must
// produce errors, never panics — no index arithmetic, no unbounded
// recursion.
func TestValidatePatch_AdversarialPaths(t *testing.T) {
	snapshot := map[string]interface{}{"a": map[string]interface{}{"b": 1}}
	paths := []string{
		"/",
		"//",
		"///",
		"/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z",
		"/~~~~~~",
		"/a/~",
		"/~0~1~0~1/~2/~01/~~",
		"/a/b/../c",
		"/a/b//c",
	}
	for _, path := range paths {
		if err := validatePatch([]patchOp{{Op: "remove", Path: path}}, snapshot); err == nil {
			t.Errorf("remove %s: nil, want error", path)
		}
	}
}
