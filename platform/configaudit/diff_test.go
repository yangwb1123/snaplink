package configaudit

import (
	"sort"
	"testing"
)

func opKey(o Op) string { return o.Op + " " + o.Path }

func TestDiff_AddReplaceRemove(t *testing.T) {
	before := map[string]any{
		"a": "1",
		"b": map[string]any{"x": float64(1), "y": "keep"},
		"c": "gone",
	}
	after := map[string]any{
		"a": "2",
		"b": map[string]any{"x": float64(2), "y": "keep"},
		"d": "new",
	}
	ops := Diff(before, after)

	got := map[string]Op{}
	for _, o := range ops {
		got[opKey(o)] = o
	}

	if op, ok := got["replace /a"]; !ok || op.Value != "2" {
		t.Errorf("expected replace /a -> 2, got %+v (present=%v)", op, ok)
	}
	if op, ok := got["replace /b/x"]; !ok || op.Value != float64(2) {
		t.Errorf("expected replace /b/x -> 2, got %+v (present=%v)", op, ok)
	}
	if _, ok := got["replace /b/y"]; ok {
		t.Errorf("unchanged /b/y must not produce an op")
	}
	if _, ok := got["remove /c"]; !ok {
		t.Errorf("expected remove /c")
	}
	if op, ok := got["add /d"]; !ok || op.Value != "new" {
		t.Errorf("expected add /d -> new, got %+v (present=%v)", op, ok)
	}
	if len(ops) != 4 {
		t.Errorf("expected exactly 4 ops, got %d: %+v", len(ops), ops)
	}
}

func TestDiff_NoChange(t *testing.T) {
	snap := map[string]any{"a": "1", "nested": map[string]any{"b": float64(2)}}
	ops := Diff(snap, snap)
	if len(ops) != 0 {
		t.Errorf("identical snapshots must diff to zero ops, got %+v", ops)
	}
}

func TestDiff_ArrayIsWholeValueReplace(t *testing.T) {
	// Documented limit: arrays are NOT diffed element-wise — a single
	// changed element still produces one whole-array "replace".
	before := map[string]any{"list": []any{"a", "b", "c"}}
	after := map[string]any{"list": []any{"a", "X", "c"}}
	ops := Diff(before, after)
	if len(ops) != 1 || ops[0].Op != "replace" || ops[0].Path != "/list" {
		t.Fatalf("expected a single whole-array replace, got %+v", ops)
	}
	arr, ok := ops[0].Value.([]any)
	if !ok || len(arr) != 3 || arr[1] != "X" {
		t.Errorf("replace value should be the full new array, got %+v", ops[0].Value)
	}
}

func TestDiff_TypeChangeIsReplace(t *testing.T) {
	before := map[string]any{"v": "1"}
	after := map[string]any{"v": float64(1)}
	ops := Diff(before, after)
	if len(ops) != 1 || ops[0].Op != "replace" {
		t.Fatalf("expected a single replace for a type change, got %+v", ops)
	}
}

func TestDiff_DeterministicOrder(t *testing.T) {
	before := map[string]any{"z": "1", "a": "1", "m": "1"}
	after := map[string]any{"z": "2", "a": "2", "m": "2"}
	ops := Diff(before, after)
	var paths []string
	for _, o := range ops {
		paths = append(paths, o.Path)
	}
	if !sort.StringsAreSorted(paths) {
		t.Errorf("Diff output must be sorted by path, got %v", paths)
	}
}

func TestDiff_KeyEscaping(t *testing.T) {
	before := map[string]any{}
	after := map[string]any{"a/b~c": "v"}
	ops := Diff(before, after)
	if len(ops) != 1 || ops[0].Path != "/a~1b~0c" {
		t.Fatalf("expected RFC 6901 escaped path /a~1b~0c, got %+v", ops)
	}
	if lastPathSegment(ops[0].Path) != "a/b~c" {
		t.Errorf("lastPathSegment must unescape, got %q", lastPathSegment(ops[0].Path))
	}
}

func TestDiff_NilMapsAreEmpty(t *testing.T) {
	ops := Diff(nil, nil)
	if len(ops) != 0 {
		t.Errorf("nil vs nil must diff to zero ops, got %+v", ops)
	}
	ops = Diff(nil, map[string]any{"a": "1"})
	if len(ops) != 1 || ops[0].Op != "add" {
		t.Errorf("nil before must treat every after key as added, got %+v", ops)
	}
}
