package oauthwire

import (
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
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
	ct := r.Header.Get(core.HeaderContentType)
	// Strip parameters (charset, boundary, …) — "application/json; charset=utf-8".
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	ct = strings.ToLower(strings.TrimSpace(ct))

	switch ct {
	case "application/x-www-form-urlencoded":
		if err := r.ParseForm(); err != nil {
			return err
		}
		return formIntoStruct(r.PostForm, v)
	default:
		// Default to JSON for "application/json", missing CT, or
		// anything unexpected. The original Bind contract.
		return json.NewDecoder(r.Body).Decode(v)
	}
}

// formIntoStruct decodes url.Values into the target struct using the
// destination's `json:"field_name"` tags as keys. Supports the
// subset of types OAuth request bodies use: string, bool, []string.
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
		setFormField(f, raw)
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

// setFormField writes raw form values into a settable struct field for
// the subset of types OAuth request bodies use: string, bool, []string.
func setFormField(f reflect.Value, raw []string) {
	switch f.Kind() {
	case reflect.String:
		f.SetString(raw[0])
	case reflect.Bool:
		f.SetBool(raw[0] == "true" || raw[0] == "1")
	case reflect.Slice:
		if f.Type().Elem().Kind() == reflect.String {
			f.Set(reflect.ValueOf(formStringSlice(raw)))
		}
	}
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
