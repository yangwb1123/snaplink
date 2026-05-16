package parse

import "testing"

func TestValue_Bool(t *testing.T) {
	if v := Value("true"); v != true {
		t.Errorf("Value(true) = %v (%T) want bool true", v, v)
	}
}

func TestValue_Int(t *testing.T) {
	switch Value("42").(type) {
	case int, int64, uint64, float64:
		// ok — yaml-numeric
	default:
		t.Errorf("Value(42) = %T want numeric", Value("42"))
	}
}

func TestValue_EmptyIsEmptyString(t *testing.T) {
	if v := Value(""); v != "" {
		t.Errorf("Value(\"\") = %v (%T) want empty string", v, v)
	}
}

func TestValue_DurationLikePassesThroughAsString(t *testing.T) {
	if v := Value("5s"); v != "5s" {
		t.Errorf("Value(5s) = %v (%T) want raw string for downstream time.Duration parse", v, v)
	}
}

func TestSetPath_Single(t *testing.T) {
	m := map[string]any{}
	SetPath(m, []string{"a"}, 1)
	if m["a"] != 1 {
		t.Errorf("a = %v", m["a"])
	}
}

func TestSetPath_Nested(t *testing.T) {
	m := map[string]any{}
	SetPath(m, []string{"a", "b", "c"}, "x")
	abc := m["a"].(map[string]any)["b"].(map[string]any)["c"]
	if abc != "x" {
		t.Errorf("a.b.c = %v", abc)
	}
}

func TestSetPath_OverwritesScalarWithMapOnConflict(t *testing.T) {
	m := map[string]any{"a": "leaf"}
	SetPath(m, []string{"a", "b"}, 1)
	if _, ok := m["a"].(map[string]any); !ok {
		t.Errorf("expected a to be promoted to map, got %T", m["a"])
	}
}

func TestSetPath_EmptyPathNoOp(t *testing.T) {
	m := map[string]any{"x": 1}
	SetPath(m, nil, "ignored")
	if len(m) != 1 || m["x"] != 1 {
		t.Errorf("empty path should not modify: %v", m)
	}
}
