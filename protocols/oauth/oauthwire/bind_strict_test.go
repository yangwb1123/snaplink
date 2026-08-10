package oauthwire

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

// strictBindTarget mirrors the field subset the credential request
// structs rely on (string + []string paths of formIntoStruct).
type strictBindTarget struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scope        []string `json:"scope"`
}

// zeroTarget reports whether v is untouched (deeply equal to the zero
// value) — the pinned contract for the 415 path and ParseForm errors.
func zeroTarget(v strictBindTarget) bool {
	return v.ClientID == "" && v.ClientSecret == "" && len(v.Scope) == 0
}

func strictCtx(ct, body string) (core.HandlerContext, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	if ct != "" {
		req.Header.Set(core.HeaderContentType, ct)
	} else {
		req.Header.Del(core.HeaderContentType)
	}
	rec := httptest.NewRecorder()
	return core.NewContext(rec, req), rec
}

func TestBindParamsFormOnly_FormBinds(t *testing.T) {
	// D5: parameter stripping + lowercase tolerance preserved — a charset
	// parameter and a mixed-case media type both bind.
	for _, ct := range []string{
		"application/x-www-form-urlencoded",
		"application/x-www-form-urlencoded; charset=UTF-8",
		"Application/X-WWW-Form-Urlencoded",
	} {
		ctx, _ := strictCtx(ct, "client_id=abc&scope=openid%20profile")
		var v strictBindTarget
		if err := BindParamsFormOnly(ctx, &v); err != nil {
			t.Fatalf("CT %q: bind error: %v", ct, err)
		}
		if v.ClientID != "abc" || len(v.Scope) != 2 || v.Scope[0] != "openid" || v.Scope[1] != "profile" {
			t.Fatalf("CT %q: bound %+v, want client_id=abc scope=[openid profile]", ct, v)
		}
	}
}

func TestBindParamsFormOnly_RejectsNonForm(t *testing.T) {
	// D5 rows: JSON, missing CT, multipart, text/plain, whitespace-only CT
	// and a JSON-with-charset variant all collapse to ErrFormOnly.
	for _, ct := range []string{
		"application/json",
		"application/json; charset=utf-8",
		"",
		"   ",
		"multipart/form-data; boundary=x",
		"text/plain",
	} {
		ctx, _ := strictCtx(ct, "client_id=abc")
		var v strictBindTarget
		err := BindParamsFormOnly(ctx, &v)
		if !errors.Is(err, ErrFormOnly) {
			t.Errorf("CT %q: err=%v, want ErrFormOnly", ct, err)
		}
		if !zeroTarget(v) {
			t.Errorf("CT %q: target partially bound: %+v", ct, v)
		}
	}
}

func TestBindParamsFormOnly_FormCTWithUnexpectedBodyStillBinds(t *testing.T) {
	// D5 row: a JSON-looking body under a form Content-Type binds to a
	// zero struct (media-type dispatch only; the per-endpoint validation
	// layer owns body semantics) — byte-identical to BindParams's form
	// path, so the strict binder never becomes a body-validation oracle.
	ctx, _ := strictCtx("application/x-www-form-urlencoded", `{"client_id":"abc"}`)
	var v strictBindTarget
	if err := BindParamsFormOnly(ctx, &v); err != nil {
		t.Fatalf("bind error: %v", err)
	}
	if !zeroTarget(v) {
		t.Fatalf("bound %+v, want zero struct (JSON-looking body under form CT)", v)
	}
}

func TestBindParamsFormOnly_EmptyFormBody(t *testing.T) {
	// D5 row: empty body WITH the form CT binds successfully to a zero
	// struct — the endpoint's unchanged 400 validation (not the binder)
	// rejects it.
	ctx, _ := strictCtx("application/x-www-form-urlencoded", "")
	var v strictBindTarget
	if err := BindParamsFormOnly(ctx, &v); err != nil {
		t.Fatalf("empty form body must bind: %v", err)
	}
	if !zeroTarget(v) {
		t.Fatalf("bound %+v, want zero struct", v)
	}
}

func TestBindParamsFormOnly_MalformedPercentEncoding(t *testing.T) {
	// F6/D5: %ZZ under a form CT is a ParseForm error — never ErrFormOnly,
	// never a partial bind. The 415 media-type branch is unreachable.
	ctx, _ := strictCtx("application/x-www-form-urlencoded", "client_id=%ZZ")
	var v strictBindTarget
	err := BindParamsFormOnly(ctx, &v)
	if err == nil {
		t.Fatal("want ParseForm error for %ZZ body")
	}
	if errors.Is(err, ErrFormOnly) {
		t.Fatalf("malformed percent-encoding must NOT be ErrFormOnly: %v", err)
	}
	if !zeroTarget(v) {
		t.Fatalf("target partially bound before ParseForm error: %+v", v)
	}
}

func TestBindParamsFormOnly_DoesNotReadBodyOn415(t *testing.T) {
	// D2/D5: the rejection fires before the body is read — a body that
	// would otherwise bind (or is malformed garbage) is irrelevant.
	for _, body := range []string{"client_id=abc", "%ZZ", "\x00\x01\xff"} {
		ctx, _ := strictCtx("application/json", body)
		var v strictBindTarget
		if err := BindParamsFormOnly(ctx, &v); !errors.Is(err, ErrFormOnly) {
			t.Errorf("body %q: err=%v, want ErrFormOnly", body, err)
		}
		if !zeroTarget(v) {
			t.Errorf("body %q: target partially bound: %+v", body, v)
		}
	}
}

func TestBindParamsFormOnly_ErrorNotWrapped(t *testing.T) {
	// D5 row: the sentinel is returned bare — errors.Is must hold for
	// both the sentinel itself and the wrapped form.
	ctx, _ := strictCtx("application/json", "")
	err := BindParamsFormOnly(ctx, &strictBindTarget{})
	if err != ErrFormOnly {
		t.Fatalf("err = %v, want the bare ErrFormOnly sentinel", err)
	}
	if !errors.Is(err, ErrFormOnly) {
		t.Fatal("errors.Is(err, ErrFormOnly) = false for the bare sentinel")
	}
}

func TestBindParamsFormOnly_PostFormOnly(t *testing.T) {
	// Form values come from the parsed POST body, never the URL query —
	// same contract as BindParams's form path.
	req := httptest.NewRequest(http.MethodPost, "/token?client_id=query", bytes.NewReader([]byte("client_id=body")))
	req.Header.Set(core.HeaderContentType, "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, req)
	var v strictBindTarget
	if err := BindParamsFormOnly(ctx, &v); err != nil {
		t.Fatalf("bind error: %v", err)
	}
	if v.ClientID != "body" {
		t.Fatalf("client_id = %q, want %q (query must not leak into PostForm)", v.ClientID, "body")
	}
}
