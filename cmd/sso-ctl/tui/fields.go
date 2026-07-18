package tui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// fieldKind says how a form field's raw textinput string round-trips to and
// from a JSON payload value. The TUI intentionally keeps every field a
// single-line text entry (no repeatable widgets) — csv/kv are just a text
// convention layered on top, matching the "key=value,key2=value2" pattern
// the task's --attr flag also uses on the entitiescmd CLI.
type fieldKind int

const (
	kindText fieldKind = iota
	kindBool
	kindCSV
	kindKV
)

// fieldSpec describes one form field: its JSON key, its on-screen label, how
// to parse it, and (for edit forms) the pre-filled initial text.
type fieldSpec struct {
	Key     string
	Label   string
	Kind    fieldKind
	Initial string
}

// buildPayload turns a form's raw field strings back into a JSON-marshalable
// map, keyed exactly as the admin API expects (see entities.go).
func buildPayload(specs []fieldSpec, raws []string) map[string]any {
	payload := make(map[string]any, len(specs))
	for i, spec := range specs {
		raw := ""
		if i < len(raws) {
			raw = raws[i]
		}
		payload[spec.Key] = parseFieldValue(spec.Kind, raw)
	}
	return payload
}

func parseFieldValue(kind fieldKind, raw string) any {
	switch kind {
	case kindBool:
		return parseBoolText(raw)
	case kindCSV:
		return splitCSV(raw)
	case kindKV:
		return splitKV(raw)
	default:
		return raw
	}
}

func parseBoolText(raw string) bool {
	b, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	return b
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitKV(raw string) map[string]string {
	out := map[string]string{}
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			continue
		}
		out[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}
	return out
}

// asString renders a decoded-JSON value (string/number/bool/nil) as display
// text for a list row or a pre-filled form field.
func asString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	default:
		return fmt.Sprintf("%v", t)
	}
}

func asBoolText(v any) string {
	b, ok := v.(bool)
	if !ok {
		return "false"
	}
	return strconv.FormatBool(b)
}

// joinCSV renders a decoded JSON array (e.g. allowed_regions) back into the
// comma-separated text an edit form's textinput pre-fills.
func joinCSV(v any) string {
	list, ok := v.([]any)
	if !ok {
		return ""
	}
	parts := make([]string, 0, len(list))
	for _, e := range list {
		parts = append(parts, asString(e))
	}
	return strings.Join(parts, ",")
}

// joinKV renders a decoded JSON object (e.g. settings/attributes) back into
// "key=value,key2=value2" text. Keys are sorted so the pre-filled text is
// stable across requests, not dependent on Go's randomized map iteration.
func joinKV(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+asString(m[k]))
	}
	return strings.Join(parts, ",")
}
