package oauthwire

// F1 decoder tests (B4-4 SDK merge interlock, reconciliation D6): the
// shared form path must decode complex JSON parameters (RFC 9396 §3
// authorization_details, OIDC Core §5.5 claims) from their JSON-string
// form-encoding, byte-identically across BindParams and
// BindParamsFormOnly, and reject invalid JSON text at bind time exactly
// like the JSON body path rejects invalid JSON at decode time — never
// silently dropping the value.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

// rawMessageBindTarget mirrors the RawMessage-bearing subset of the
// credential request structs (parRequestForm, login.Request).
type rawMessageBindTarget struct {
	ClientID             string          `json:"client_id"`
	AuthorizationDetails json.RawMessage `json:"authorization_details"` // RFC 9396 §3
	Claims               json.RawMessage `json:"claims"`                // OIDC Core §5.5
	Scope                []string        `json:"scope"`
}

func rawMessageCtx(body string) (core.HandlerContext, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(http.MethodPost, "/par", strings.NewReader(body))
	req.Header.Set(core.HeaderContentType, "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	return core.NewContext(rec, req), rec
}

const claimsJSON = `{"userinfo":{"email":null,"name":{"essential":true}},"id_token":{"email":null}}`

func TestFormRawMessage_BindsVerbatim(t *testing.T) {
	// The form value IS the JSON text; the bound RawMessage must carry
	// it verbatim (same bytes the JSON body path captures for
	// {"claims": <value>}), for both the dual-mode and strict binders.
	for _, binder := range []string{"dual", "strict"} {
		body := "client_id=abc&scope=openid%20profile" +
			"&claims=" + claimsJSON +
			"&authorization_details=" + `[{"type":"payment_initiation"}]`
		ctx, _ := rawMessageCtx(body)
		var v rawMessageBindTarget
		var err error
		if binder == "strict" {
			err = BindParamsFormOnly(ctx, &v)
		} else {
			err = BindParams(ctx, &v)
		}
		if err != nil {
			t.Fatalf("%s binder: %v", binder, err)
		}
		if string(v.Claims) != claimsJSON {
			t.Errorf("%s binder: claims = %s, want verbatim %s", binder, v.Claims, claimsJSON)
		}
		if want := `[{"type":"payment_initiation"}]`; string(v.AuthorizationDetails) != want {
			t.Errorf("%s binder: authorization_details = %s, want %s", binder, v.AuthorizationDetails, want)
		}
		if !reflect.DeepEqual(v.Scope, []string{"openid", "profile"}) {
			t.Errorf("%s binder: scope = %v", binder, v.Scope)
		}
	}
}

func TestFormRawMessage_PercentEncodedJSON(t *testing.T) {
	// url.Values.Encode percent-encodes the braces/quotes; ParseForm
	// must round-trip them back to the original JSON text.
	form := url.Values{"claims": {claimsJSON}}
	ctx, _ := rawMessageCtx(form.Encode())
	var v rawMessageBindTarget
	if err := BindParamsFormOnly(ctx, &v); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if string(v.Claims) != claimsJSON {
		t.Errorf("claims = %s, want %s", v.Claims, claimsJSON)
	}
}

func TestFormRawMessage_RejectsInvalidJSON(t *testing.T) {
	// Parity with the JSON body path: invalid JSON fails at decode/bind
	// time (400 invalid_request at the handler), never stored as garbage.
	for _, binder := range []string{"dual", "strict"} {
		for _, bad := range []string{"{", "not-json", "", "[1,", `{"a":`} {
			ctx, _ := rawMessageCtx("claims=" + bad)
			var v rawMessageBindTarget
			var err error
			if binder == "strict" {
				err = BindParamsFormOnly(ctx, &v)
			} else {
				err = BindParams(ctx, &v)
			}
			if err == nil {
				t.Errorf("%s binder: claims=%q bound without error (want bind error)", binder, bad)
			}
		}
	}
}

func TestFormRawMessage_ZeroValueWithoutKey(t *testing.T) {
	// No claims key in the form → field stays nil, matching the JSON
	// path where an absent member leaves RawMessage nil.
	ctx, _ := rawMessageCtx("client_id=abc")
	var v rawMessageBindTarget
	if err := BindParamsFormOnly(ctx, &v); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if v.Claims != nil || v.AuthorizationDetails != nil {
		t.Errorf("absent keys must leave RawMessage nil: claims=%s details=%s", v.Claims, v.AuthorizationDetails)
	}
}

func TestFormRawMessage_DecodedValueMustBeJSON(t *testing.T) {
	// A JSON-looking STRING in the JSON body path lands in RawMessage
	// WITH its quotes (the raw JSON encoding). The form path must not
	// re-encode: the client's form value is the document itself.
	ctx, _ := rawMessageCtx("claims=" + `"just-a-string"`)
	var v rawMessageBindTarget
	if err := BindParamsFormOnly(ctx, &v); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if want := `"just-a-string"`; string(v.Claims) != want {
		t.Errorf("claims = %s, want %s (verbatim JSON text)", v.Claims, want)
	}
	if !json.Valid(v.Claims) {
		t.Errorf("claims %s must be valid JSON text", v.Claims)
	}
}
