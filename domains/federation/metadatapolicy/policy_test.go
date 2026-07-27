package metadatapolicy

import (
	"testing"
)

func TestMergePolicies(t *testing.T) {
	t.Run("empty list returns empty map", func(t *testing.T) {
		result, err := MergePolicies(nil)
		if err != nil {
			t.Fatalf("MergePolicies(nil): %v", err)
		}
		if result == nil {
			t.Error("expected non-nil empty map")
		}
		if len(result) != 0 {
			t.Errorf("expected empty map, got %v", result)
		}
	})

	t.Run("single policy", func(t *testing.T) {
		policies := []map[string]map[string]any{
			{"redirect_uris": {"value": []string{"https://example.com/cb"}}},
		}
		result, err := MergePolicies(policies)
		if err != nil {
			t.Fatalf("MergePolicies: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if _, ok := result["redirect_uris"]; !ok {
			t.Error("expected redirect_uris in result")
		}
	})
}

func TestApplyParamPolicy(t *testing.T) {
	t.Run("nil policy is no-op", func(t *testing.T) {
		err := applyParamPolicy("test", nil, map[string]any{"value": "x"})
		if err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
	})

	t.Run("empty policy is no-op", func(t *testing.T) {
		err := applyParamPolicy("test", paramPolicy{}, map[string]any{"value": "x"})
		if err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
	})
}

func TestHasOp(t *testing.T) {
	t.Run("op present", func(t *testing.T) {
		pp := paramPolicy{"essential": true}
		if !hasOp(pp, "essential") {
			t.Error("expected essential op to be found")
		}
	})

	t.Run("op absent", func(t *testing.T) {
		pp := paramPolicy{"value": "x"}
		if hasOp(pp, "essential") {
			t.Error("expected essential op not to be found")
		}
	})

	t.Run("nil policy", func(t *testing.T) {
		if hasOp(nil, "essential") {
			t.Error("expected false for nil policy")
		}
	})
}

func TestApplyOneOf(t *testing.T) {
	t.Run("operand in one_of", func(t *testing.T) {
		pp := paramPolicy{"one_of": []any{"a", "b", "c"}}
		err := applyOneOf("test", pp, map[string]any{"test": "a"})
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("operand not in one_of", func(t *testing.T) {
		pp := paramPolicy{"one_of": []any{"a", "b"}}
		err := applyOneOf("test", pp, map[string]any{"test": "z"})
		if err == nil {
			t.Error("expected error for value not in one_of")
		}
	})

	t.Run("missing param ignored", func(t *testing.T) {
		pp := paramPolicy{"one_of": []any{"a", "b"}}
		err := applyOneOf("other", pp, map[string]any{"test": "a"})
		if err != nil {
			t.Errorf("expected nil for missing param, got %v", err)
		}
	})
}

func TestApplyEssential(t *testing.T) {
	t.Run("essential param present", func(t *testing.T) {
		pp := paramPolicy{"essential": true}
		err := applyParamEssential("test", pp, map[string]any{"test": "value"})
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("essential param missing", func(t *testing.T) {
		pp := paramPolicy{"essential": true}
		err := applyParamEssential("test", pp, map[string]any{"other": "value"})
		if err == nil {
			t.Error("expected error for missing essential param")
		}
	})

	t.Run("essential false is no-op", func(t *testing.T) {
		pp := paramPolicy{"essential": false}
		err := applyParamEssential("test", pp, map[string]any{})
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})
}

func TestApplySubsetOf(t *testing.T) {
	t.Run("valid subset", func(t *testing.T) {
		pp := paramPolicy{"subset_of": []any{"openid", "profile", "email"}}
		err := applySubsetOf("test", pp, map[string]any{"test": []any{"openid", "profile"}})
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("invalid subset", func(t *testing.T) {
		pp := paramPolicy{"subset_of": []any{"openid"}}
		err := applySubsetOf("test", pp, map[string]any{"test": []any{"openid", "admin"}})
		if err == nil {
			t.Error("expected error for invalid subset")
		}
	})

	t.Run("missing param ignored", func(t *testing.T) {
		pp := paramPolicy{"subset_of": []any{"openid"}}
		err := applySubsetOf("other", pp, map[string]any{"test": "x"})
		if err != nil {
			t.Errorf("expected nil for missing param, got %v", err)
		}
	})
}

func TestApplySupersetOf(t *testing.T) {
	t.Run("valid superset", func(t *testing.T) {
		pp := paramPolicy{"superset_of": []any{"openid"}}
		err := applySupersetOf("test", pp, map[string]any{"test": []any{"openid", "profile"}})
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("invalid superset", func(t *testing.T) {
		pp := paramPolicy{"superset_of": []any{"openid", "profile"}}
		err := applySupersetOf("test", pp, map[string]any{"test": []any{"openid"}})
		if err == nil {
			t.Error("expected error for invalid superset")
		}
	})
}
