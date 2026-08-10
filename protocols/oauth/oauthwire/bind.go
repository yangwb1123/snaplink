package oauthwire

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/yangwb1123/snaplink/shared/core"
)

// BindParams reads OAuth request parameters from either a JSON
// body or a form-encoded body, dispatched by Content-Type. RFC 6749
// §3.2 + RFC 7662 §2.1 + RFC 7009 §2.1 + RFC 8628 §3.1 all mandate
// application/x-www-form-urlencoded for these endpoints — every
// off-the-shelf OAuth client library sends form-encoded by default.
// JSON is accepted as a non-standard convenience for SPAs and
// internal callers that already speak JSON natively.
//
// Decoding follows the struct's `json` tags so existing request
// structs work unmodified for both wire formats.
//
// Empty body + no Content-Type is treated as JSON for backward
// compatibility with the original SDK behavior.
func BindParams(ctx core.HandlerContext, v any) error {
	r := ctx.Request()
	switch normalizedMediaType(r) {
	case "application/x-www-form-urlencoded":
		return bindForm(r, v)
	default:
		// Default to JSON for "application/json", missing CT, or
		// anything unexpected. The original Bind contract.
		//
		// REGRESSION BOUNDARY (B4-4): this JSON/missing-CT default is
		// load-bearing — non-credential consumers (commerce, admin,
		// selfservice) and the default-off baseline depend on it. Never
		// "clean it up" into a global form-only flip; the strict
		// enforcement lives in BindParamsFormOnly (bind_strict.go) and
		// is opt-in per deployment.
		return decodeSingleJSON(r.Body, v)
	}
}

// normalizedMediaType returns the request's Content-Type with
// parameters (charset, boundary, …) stripped and lowercased, e.g.
// "application/json; charset=utf-8" → "application/json". An empty
// or whitespace-only header normalizes to "".
func normalizedMediaType(r *http.Request) string {
	ct := r.Header.Get(core.HeaderContentType)
	// Strip parameters (charset, boundary, …) — "application/json; charset=utf-8".
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

// bindForm parses the request body as application/x-www-form-urlencoded
// into v via formIntoStruct (multi-value + space-separated handling
// included). Shared byte-identically by BindParams and
// BindParamsFormOnly.
func bindForm(r *http.Request, v any) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	return formIntoStruct(r.PostForm, v)
}

func decodeSingleJSON(body io.Reader, target any) error {
	decoder := json.NewDecoder(body)
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("oauth: request body must contain one JSON value")
		}
		return err
	}
	return nil
}

// rawMessageType is the reflect type of json.RawMessage, matched by
// exact type identity so plain []byte fields (none in the request
// structs today) are never misinterpreted as JSON text.
var rawMessageType = reflect.TypeOf(json.RawMessage{})

// formIntoStruct decodes url.Values into the target struct using the
// destination's `json:"field_name"` tags as keys. Supports the
// subset of types OAuth request bodies use: string, bool, integer pointers,
// []string, and json.RawMessage (RFC 9396 §3 / OIDC Core §5.5 complex
// JSON parameters).
func formIntoStruct(form url.Values, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() || rv.Elem().Kind() != reflect.Struct {
		return errors.New("oauth: BindParams target must be *struct")
	}
	rv = rv.Elem()
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		tag := formFieldKey(rt.Field(i))
		if tag == "" {
			continue
		}
		raw, ok := form[tag]
		if !ok || len(raw) == 0 {
			continue
		}
		f := rv.Field(i)
		if !f.CanSet() {
			continue
		}
		if err := setFormField(tag, f, raw); err != nil {
			return err
		}
	}
	return nil
}

// formFieldKey derives the form key for a struct field from its `json`
// tag, returning "" for untagged or skipped fields. Mirrors the subset
// of encoding/json tag handling the request structs rely on.
func formFieldKey(field reflect.StructField) string {
	tag := field.Tag.Get("json")
	if tag == "" || tag == "-" {
		return ""
	}
	// Strip ",omitempty" and friends.
	if i := strings.IndexByte(tag, ','); i >= 0 {
		tag = tag[:i]
	}
	return tag
}

// setFormField writes raw form values into a supported struct field.
// key is the form key (from the json tag) and appears only in error
// messages.
func setFormField(key string, f reflect.Value, raw []string) error {
	switch f.Kind() {
	case reflect.String:
		f.SetString(raw[0])
	case reflect.Bool:
		f.SetBool(raw[0] == "true" || raw[0] == "1")
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return setFormInt(f, raw[0])
	case reflect.Pointer:
		if f.Type().Elem().Kind() == reflect.Int {
			value := reflect.New(f.Type().Elem())
			if err := setFormInt(value.Elem(), raw[0]); err != nil {
				return err
			}
			f.Set(value)
		}
	case reflect.Slice:
		if f.Type() == rawMessageType {
			// RFC 9396 §3 / OIDC Core §5.5: complex JSON parameters
			// (claims, authorization_details) travel as a JSON-encoded
			// string in form-encoded requests. The JSON body path
			// captures the raw JSON value verbatim and rejects invalid
			// JSON at decode time; parity requires the form value to be
			// valid JSON text too — invalid text is a bind error, never
			// a silent drop (the pre-F1 behavior lost the value).
			if !json.Valid([]byte(raw[0])) {
				return fmt.Errorf("oauth: form field %q must be a JSON value", key)
			}
			f.SetBytes([]byte(raw[0]))
			return nil
		}
		if f.Type().Elem().Kind() == reflect.String {
			f.Set(reflect.ValueOf(formStringSlice(raw)))
		}
	}
	return nil
}

func setFormInt(f reflect.Value, raw string) error {
	n, err := strconv.ParseInt(raw, 10, f.Type().Bits())
	if err != nil {
		return err
	}
	f.SetInt(n)
	return nil
}

// formStringSlice flattens raw form values into a []string, honoring both
// "scope=a&scope=b" (multi-value) and "scope=a%20b" (space-separated
// single value) per RFC 6749 §3.3. Token endpoint uses the latter almost
// universally.
func formStringSlice(raw []string) []string {
	if len(raw) == 1 && strings.ContainsAny(raw[0], " ,") {
		sep := " "
		if strings.Contains(raw[0], ",") && !strings.Contains(raw[0], " ") {
			sep = ","
		}
		return strings.Split(raw[0], sep)
	}
	return append([]string(nil), raw...)
}
