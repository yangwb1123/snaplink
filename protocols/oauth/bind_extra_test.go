package oauth

import (
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

// bindTarget exercises every branch of formIntoStruct: string, bool,
// []string (multi-value + space + comma separated), the skip rules for
// untagged / "-" / unexported fields.
type bindTarget struct {
	Grant    string   `json:"grant_type"`
	Flag     bool     `json:"flag"`
	Scope    []string `json:"scope"`
	Resource []string `json:"resource"`
	Count    int      `json:"count"`
	Expiry   *int     `json:"expiry"`
	Skipped  string   `json:"-"`
	NoTag    string
	unexp    string //nolint:unused // present to exercise the CanSet skip
}

func bindForm(t *testing.T, body string, v any) error {
	t.Helper()
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set(core.HeaderContentType, "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	return BindParams(core.NewContext(rec, req), v)
}

func TestFormIntoStruct(t *testing.T) {
	t.Parallel()
	t.Run("string and bool", func(t *testing.T) {
		var got bindTarget
		if err := bindForm(t, "grant_type=authorization_code&flag=true", &got); err != nil {
			t.Fatal(err)
		}
		if got.Grant != "authorization_code" {
			t.Errorf("grant = %q", got.Grant)
		}
		if !got.Flag {
			t.Error("flag should be true")
		}
	})

	t.Run("bool accepts 1", func(t *testing.T) {
		var got bindTarget
		if err := bindForm(t, "flag=1", &got); err != nil {
			t.Fatal(err)
		}
		if !got.Flag {
			t.Error("flag=1 should be true")
		}
	})

	t.Run("bool false for other values", func(t *testing.T) {
		var got bindTarget
		if err := bindForm(t, "flag=yes", &got); err != nil {
			t.Fatal(err)
		}
		if got.Flag {
			t.Error("flag=yes should be false (only true/1)")
		}
	})

	t.Run("integer and optional integer", func(t *testing.T) {
		var got bindTarget
		if err := bindForm(t, "count=7&expiry=12", &got); err != nil {
			t.Fatal(err)
		}
		if got.Count != 7 || got.Expiry == nil || *got.Expiry != 12 {
			t.Fatalf("integers = %d %v, want 7 and 12", got.Count, got.Expiry)
		}
	})

	t.Run("malformed integer errors", func(t *testing.T) {
		var got bindTarget
		if err := bindForm(t, "expiry=not-a-number", &got); err == nil {
			t.Fatal("malformed integer should fail binding")
		}
	})

	t.Run("space-separated scope single value", func(t *testing.T) {
		var got bindTarget
		if err := bindForm(t, "scope=openid+profile+email", &got); err != nil {
			t.Fatal(err)
		}
		want := []string{"openid", "profile", "email"}
		if !reflect.DeepEqual(got.Scope, want) {
			t.Errorf("scope = %v, want %v", got.Scope, want)
		}
	})

	t.Run("comma-separated single value", func(t *testing.T) {
		var got bindTarget
		// resource=a,b with no space → split on comma per RFC 6749 §3.3 note
		if err := bindForm(t, "resource=a,b,c", &got); err != nil {
			t.Fatal(err)
		}
		want := []string{"a", "b", "c"}
		if !reflect.DeepEqual(got.Resource, want) {
			t.Errorf("resource = %v, want %v", got.Resource, want)
		}
	})

	t.Run("multi-value repeated key", func(t *testing.T) {
		var got bindTarget
		if err := bindForm(t, "resource=https://a&resource=https://b", &got); err != nil {
			t.Fatal(err)
		}
		want := []string{"https://a", "https://b"}
		if !reflect.DeepEqual(got.Resource, want) {
			t.Errorf("resource = %v, want %v", got.Resource, want)
		}
	})

	t.Run("dash tag and untagged fields skipped", func(t *testing.T) {
		var got bindTarget
		// Even if the form names them, the "-" tag and the untagged field
		// must be ignored (untagged field has no json key to match).
		if err := bindForm(t, "Skipped=x&NoTag=y", &got); err != nil {
			t.Fatal(err)
		}
		if got.Skipped != "" || got.NoTag != "" {
			t.Errorf("skipped=%q notag=%q, both want empty", got.Skipped, got.NoTag)
		}
	})

	t.Run("non-pointer target errors", func(t *testing.T) {
		var got bindTarget
		if err := bindForm(t, "grant_type=x", got); err == nil {
			t.Error("binding into a non-pointer should error")
		}
	})

	t.Run("nil pointer errors", func(t *testing.T) {
		var p *bindTarget
		if err := bindForm(t, "grant_type=x", p); err == nil {
			t.Error("binding into a nil pointer should error")
		}
	})
}

func TestBindParamsJSONDefault(t *testing.T) {
	t.Parallel()
	// Missing Content-Type defaults to JSON (the original SDK contract).
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"grant_type":"x"}`))
	rec := httptest.NewRecorder()
	var got bindTarget
	if err := BindParams(core.NewContext(rec, req), &got); err != nil {
		t.Fatal(err)
	}
	if got.Grant != "x" {
		t.Errorf("grant = %q, want x", got.Grant)
	}
}

func TestBindParamsContentTypeWithCharset(t *testing.T) {
	t.Parallel()
	// The charset parameter must be stripped before dispatch.
	req := httptest.NewRequest("POST", "/", strings.NewReader("grant_type=z"))
	req.Header.Set(core.HeaderContentType, "application/x-www-form-urlencoded; charset=utf-8")
	rec := httptest.NewRecorder()
	var got bindTarget
	if err := BindParams(core.NewContext(rec, req), &got); err != nil {
		t.Fatal(err)
	}
	if got.Grant != "z" {
		t.Errorf("grant = %q, want z", got.Grant)
	}
}

func TestBindParamsRejectsTrailingJSONValue(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"grant_type":"x"}{"grant_type":"y"}`))
	req.Header.Set(core.HeaderContentType, core.ContentTypeJSON)
	rec := httptest.NewRecorder()
	var got bindTarget
	if err := BindParams(core.NewContext(rec, req), &got); err == nil {
		t.Fatal("multiple JSON values must fail binding")
	}
}

// TestAuthenticateIntrospectionClientMissingCreds covers the early-return
// branch when id or secret is empty (no store round trip).
func TestAuthenticateIntrospectionClientMissingCreds(t *testing.T) {
	t.Parallel()
	cs := newMemClientStore()
	ctx, _ := newCtx("POST", core.ContentTypeJSON, `{}`)
	if err := authenticateIntrospectionClient(cs, ctx, "", "secret"); err == nil {
		t.Error("empty id should error before store lookup")
	}
	if err := authenticateIntrospectionClient(cs, ctx, "id", ""); err == nil {
		t.Error("empty secret should error before store lookup")
	}
}

// TestDedupeScopesEmptyAfterTrim covers the all-empties → nil branch.
