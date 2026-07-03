package configaudit

import "testing"

func TestIsSensitiveKey(t *testing.T) {
	cases := map[string]bool{
		"client_secret": true,
		"Password":      true,
		"DSN":           true,
		"api_token":     true,
		"signing_key":   true,
		"SECRET_VALUE":  true,
		"username":      false,
		"redirect_uris": false,
		"enabled":       false,
	}
	for name, want := range cases {
		if got := IsSensitiveKey(name); got != want {
			t.Errorf("IsSensitiveKey(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestRedactOps_ScrubsSensitiveValuesButKeepsThePath(t *testing.T) {
	ops := []Op{
		{Op: "replace", Path: "/audit/webhook/signing_secret", Value: "sup3r-secret"},
		{Op: "add", Path: "/oauth/client_secret", Value: "abc"},
		{Op: "remove", Path: "/oauth/old_password"},
		{Op: "replace", Path: "/server/name", Value: "sso-1"},
	}
	out := RedactOps(ops)

	if out[0].Value != "***" {
		t.Errorf("sensitive replace value not redacted: %+v", out[0])
	}
	if out[0].Path != ops[0].Path || out[0].Op != ops[0].Op {
		t.Errorf("redaction must preserve op + path (presence-of-change signal), got %+v", out[0])
	}
	if out[1].Value != "***" {
		t.Errorf("sensitive add value not redacted: %+v", out[1])
	}
	if out[2].Value != nil {
		t.Errorf("remove op should carry no value, got %+v", out[2])
	}
	if out[3].Value != "sso-1" {
		t.Errorf("non-sensitive value must pass through unredacted, got %+v", out[3])
	}
	// Input slice must not be mutated (RedactOps returns a copy).
	if ops[0].Value != "sup3r-secret" {
		t.Errorf("RedactOps must not mutate its input, original now %+v", ops[0])
	}
}

func TestRedact_DeepSnapshot(t *testing.T) {
	snap := map[string]any{
		"db_dsn": "postgres://user:pass@host/db",
		"server": map[string]any{
			"name":      "sso-1",
			"admin_key": "topsecret",
			"tags":      []any{"prod", map[string]any{"api_token": "xyz"}},
		},
	}
	out := Redact(snap)

	if out["db_dsn"] != "***" {
		t.Errorf("top-level sensitive key not redacted: %+v", out)
	}
	server, ok := out["server"].(map[string]any)
	if !ok {
		t.Fatalf("expected nested server map, got %T", out["server"])
	}
	if server["name"] != "sso-1" {
		t.Errorf("non-sensitive nested key must survive, got %+v", server)
	}
	if server["admin_key"] != "***" {
		t.Errorf("nested sensitive key not redacted: %+v", server)
	}
	tags, ok := server["tags"].([]any)
	if !ok || len(tags) != 2 {
		t.Fatalf("expected 2-element tags array, got %+v", server["tags"])
	}
	if tags[0] != "prod" {
		t.Errorf("non-sensitive array element must survive, got %+v", tags[0])
	}
	inner, ok := tags[1].(map[string]any)
	if !ok || inner["api_token"] != "***" {
		t.Errorf("sensitive key inside an array element must be redacted, got %+v", tags[1])
	}

	// Original snapshot must be untouched (Redact returns a deep copy).
	if snap["db_dsn"] != "postgres://user:pass@host/db" {
		t.Errorf("Redact must not mutate its input, original now %+v", snap["db_dsn"])
	}
}

func TestRedact_Nil(t *testing.T) {
	if got := Redact(nil); got != nil {
		t.Errorf("Redact(nil) = %+v, want nil", got)
	}
}
