package configaudit

import (
	"reflect"
	"sort"
	"strings"
)

// Diff computes a minimal RFC 6902 JSON Patch turning `before` into `after`.
// Intended input is two config snapshots decoded the way encoding/json
// decodes into `any` (map[string]any objects, []any arrays, and
// string/float64/bool/nil leaves) — the shape produced by
// json.Unmarshal(raw, &map[string]any{}).
//
// Documented limits (deliberately — a flat-object + nested-map diff is
// sufficient for a config-audit trail, and keeps this dependency-free):
//
//   - Objects (map[string]any) are diffed recursively, key by key.
//   - Arrays ([]any) are compared by WHOLE-VALUE equality only: a changed
//     array produces a single "replace" at the array's own path, never a
//     per-element diff. A config with array-heavy sections (e.g. a client's
//     redirect_uris list) will show the whole list replaced rather than
//     "which URI changed" — callers needing element-level array diffs
//     should diff that sub-path themselves.
//   - A value that changes TYPE (e.g. a string becomes a number) is a
//     "replace", the same as any other value change.
//   - Only add/replace/remove ops are produced — no move/copy/test. That
//     is a strict RFC 6902 subset, so every emitted patch is still a valid
//     JSON Patch; it just never uses the operations a config diff has no
//     use for.
//
// The result is sorted by Path for deterministic output (map iteration
// order is otherwise random), which also keeps tests and the audit trail
// stable across runs of the same logical diff.
func Diff(before, after map[string]any) []Op {
	var ops []Op
	diffMaps("", before, after, &ops)
	sort.Slice(ops, func(i, j int) bool { return ops[i].Path < ops[j].Path })
	return ops
}

// diffMaps recurses over the union of before/after's keys at one object
// level, appending an Op for every key that was added, removed, or whose
// value differs (see Diff's doc for the array/type-change limits).
func diffMaps(path string, before, after map[string]any, ops *[]Op) {
	seen := make(map[string]bool, len(before)+len(after))
	for k := range before {
		seen[k] = true
	}
	for k := range after {
		seen[k] = true
	}
	for k := range seen {
		childPath := path + "/" + escapePointerSegment(k)
		bv, bok := before[k]
		av, aok := after[k]
		switch {
		case !bok && aok:
			*ops = append(*ops, Op{Op: "add", Path: childPath, Value: av})
		case bok && !aok:
			*ops = append(*ops, Op{Op: "remove", Path: childPath})
		default:
			diffValue(childPath, bv, av, ops)
		}
	}
}

// diffValue compares one before/after pair already known to exist on both
// sides, recursing into nested objects and falling back to whole-value
// replace for everything else (arrays, scalars, type changes).
func diffValue(path string, before, after any, ops *[]Op) {
	bmap, bIsMap := before.(map[string]any)
	amap, aIsMap := after.(map[string]any)
	if bIsMap && aIsMap {
		diffMaps(path, bmap, amap, ops)
		return
	}
	if !reflect.DeepEqual(before, after) {
		*ops = append(*ops, Op{Op: "replace", Path: path, Value: after})
	}
}

// escapePointerSegment escapes a raw object key for use as one RFC 6901
// JSON Pointer segment ("~" -> "~0", "/" -> "~1"). Order matters: "~" must
// be escaped first so a literal "~1" in the source key isn't
// double-escaped.
func escapePointerSegment(seg string) string {
	seg = strings.ReplaceAll(seg, "~", "~0")
	seg = strings.ReplaceAll(seg, "/", "~1")
	return seg
}

// unescapePointerSegment reverses escapePointerSegment.
func unescapePointerSegment(seg string) string {
	seg = strings.ReplaceAll(seg, "~1", "/")
	seg = strings.ReplaceAll(seg, "~0", "~")
	return seg
}

// lastPathSegment returns the final, UNESCAPED segment of a JSON Pointer
// path (e.g. "/audit/webhook/signing_secret" -> "signing_secret"). Used by
// the redaction pass to test the LEAF field name against IsSensitiveKey.
func lastPathSegment(path string) string {
	idx := strings.LastIndexByte(path, '/')
	seg := path
	if idx >= 0 {
		seg = path[idx+1:]
	}
	return unescapePointerSegment(seg)
}
