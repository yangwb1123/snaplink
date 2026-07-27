package consent

import (
	"encoding/json"
	"testing"
)

func TestScopesMatch(t *testing.T) {
	t.Run("identical scopes", func(t *testing.T) {
		if !ScopesMatch([]string{"openid", "profile"}, []string{"openid", "profile"}) {
			t.Error("identical scopes should match")
		}
	})

	t.Run("different order", func(t *testing.T) {
		if !ScopesMatch([]string{"openid", "profile"}, []string{"profile", "openid"}) {
			t.Error("same scopes different order should match")
		}
	})

	t.Run("different scopes", func(t *testing.T) {
		if ScopesMatch([]string{"openid"}, []string{"openid", "profile"}) {
			t.Error("different scopes should not match")
		}
	})

	t.Run("nil vs empty", func(t *testing.T) {
		if !ScopesMatch(nil, []string{}) {
			t.Error("nil and empty should match")
		}
	})

	t.Run("both nil", func(t *testing.T) {
		if !ScopesMatch(nil, nil) {
			t.Error("nil and nil should match")
		}
	})
}

func TestHasPromptValue(t *testing.T) {
	t.Run("value present", func(t *testing.T) {
		if !HasPromptValue("consent login", "consent") {
			t.Error("expected 'consent' to be found")
		}
	})

	t.Run("value absent", func(t *testing.T) {
		if HasPromptValue("login", "consent") {
			t.Error("expected 'consent' not to be found")
		}
	})

	t.Run("empty prompt", func(t *testing.T) {
		if HasPromptValue("", "consent") {
			t.Error("expected false for empty prompt")
		}
	})

	t.Run("empty value", func(t *testing.T) {
		if HasPromptValue("consent", "") {
			t.Error("expected false for empty value")
		}
	})
}

func TestScopesSubsumed(t *testing.T) {
	t.Run("granted subsumes requested", func(t *testing.T) {
		if !ScopesSubsumed([]string{"openid", "profile", "email"}, []string{"openid", "profile"}) {
			t.Error("granted should subsume subset")
		}
	})

	t.Run("identical sets", func(t *testing.T) {
		if !ScopesSubsumed([]string{"openid"}, []string{"openid"}) {
			t.Error("identical should subsume")
		}
	})

	t.Run("granted does not subsume requested", func(t *testing.T) {
		if ScopesSubsumed([]string{"openid"}, []string{"openid", "admin"}) {
			t.Error("granted should not subsume larger set")
		}
	})

	t.Run("both nil", func(t *testing.T) {
		if !ScopesSubsumed(nil, nil) {
			t.Error("nil and nil should be subsumed")
		}
	})

	t.Run("requested nil always subsumed", func(t *testing.T) {
		if !ScopesSubsumed([]string{"openid"}, nil) {
			t.Error("nil requested should be subsumed")
		}
	})
}

func TestChallengeStoreIssueAndConsume(t *testing.T) {
	store := NewChallengeStore()

	id := store.Issue("user-1", "client-1", []string{"openid", "profile"}, nil)
	if id == "" {
		t.Fatal("expected non-empty challenge ID")
	}

	// Consume with matching params
	if !store.Consume(id, "user-1", "client-1", []string{"openid", "profile"}, nil) {
		t.Error("expected Consume to succeed")
	}

	// Second consume should fail (already consumed)
	if store.Consume(id, "user-1", "client-1", []string{"openid", "profile"}, nil) {
		t.Error("expected second Consume to fail")
	}
}

func TestChallengeStoreMismatch(t *testing.T) {
	store := NewChallengeStore()

	id := store.Issue("user-1", "client-1", []string{"openid"}, nil)

	// Wrong user
	if store.Consume(id, "user-2", "client-1", []string{"openid"}, nil) {
		t.Error("expected Consume to fail for wrong user")
	}

	// Wrong client
	if store.Consume(id, "user-1", "client-2", []string{"openid"}, nil) {
		t.Error("expected Consume to fail for wrong client")
	}

	// Different scopes
	if store.Consume(id, "user-1", "client-1", []string{"openid", "profile"}, nil) {
		t.Error("expected Consume to fail for different scopes")
	}
}

func TestChallengeStoreAuthorizationDetails(t *testing.T) {
	store := NewChallengeStore()

	details := json.RawMessage(`{"type":"account_inquiry","locations":["https://api.example.com"]}`)
	id := store.Issue("user-1", "client-1", []string{"openid"}, details)
	if id == "" {
		t.Fatal("expected non-empty challenge ID")
	}

	if !store.Consume(id, "user-1", "client-1", []string{"openid"}, details) {
		t.Error("expected Consume with matching authz details")
	}
}

func TestRawJSONEqual(t *testing.T) {
	t.Run("both nil", func(t *testing.T) {
		if !rawJSONEqual(nil, nil) {
			t.Error("nil and nil should be equal")
		}
	})

	t.Run("one nil", func(t *testing.T) {
		if rawJSONEqual(nil, json.RawMessage(`{}`)) {
			t.Error("nil and non-nil should not be equal")
		}
		if rawJSONEqual(json.RawMessage(`{}`), nil) {
			t.Error("non-nil and nil should not be equal")
		}
	})

	t.Run("same JSON", func(t *testing.T) {
		if !rawJSONEqual(
			json.RawMessage(`{"a":1,"b":2}`),
			json.RawMessage(`{"a":1,"b":2}`),
		) {
			t.Error("same JSON should be equal")
		}
	})

	t.Run("different JSON", func(t *testing.T) {
		if rawJSONEqual(
			json.RawMessage(`{"a":1}`),
			json.RawMessage(`{"a":2}`),
		) {
			t.Error("different JSON should not be equal")
		}
	})

	t.Run("key order independence", func(t *testing.T) {
		if !rawJSONEqual(
			json.RawMessage(`{"a":1,"b":2}`),
			json.RawMessage(`{"b":2,"a":1}`),
		) {
			t.Error("JSON equality should be key-order independent")
		}
	})

	t.Run("nested key order independence", func(t *testing.T) {
		if !rawJSONEqual(
			json.RawMessage(`{"outer":{"a":1,"b":[{"x":2,"y":3}]}}`),
			json.RawMessage(`{"outer":{"b":[{"y":3,"x":2}],"a":1}}`),
		) {
			t.Error("nested JSON objects should be key-order independent")
		}
	})

	t.Run("array order matters", func(t *testing.T) {
		if rawJSONEqual(
			json.RawMessage(`{"values":[1,2]}`),
			json.RawMessage(`{"values":[2,1]}`),
		) {
			t.Error("JSON array order should remain significant")
		}
	})

	t.Run("malformed JSON never matches", func(t *testing.T) {
		malformed := json.RawMessage(`{"a":`)
		if rawJSONEqual(malformed, malformed) {
			t.Error("malformed JSON should not compare equal")
		}
	})

	t.Run("large numbers retain precision", func(t *testing.T) {
		if rawJSONEqual(
			json.RawMessage(`{"n":9007199254740992}`),
			json.RawMessage(`{"n":9007199254740993}`),
		) {
			t.Error("distinct large JSON numbers should not compare equal")
		}
	})
}
