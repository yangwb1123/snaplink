package controller

import (
	"errors"
	"fmt"
	"strings"
)

// validatePatch reports whether patch could have been emitted by the
// server's documented cluster-diff contract: only add/remove/replace ops
// (platform/configaudit diff.go:27), /-rooted RFC 6901 paths whose
// segments the server's escapePointerSegment produced, and paths that
// resolve into snapshot with object-only intermediates (diffMaps recurses
// only into objects; arrays are whole-value replaced, never traversed).
// The check is a strict superset of the emit set: it rejects only shapes
// the server cannot have produced, so a legitimate response is never
// mislabeled. Errors are static reason strings plus the op index;
// response-derived bytes (op values, paths) are never echoed, and the
// function receives neither tokens nor requests, so nothing
// server-authored or credential-bearing can reach Status.Message (see
// the B4-3 truthiness design doc, D-D).
func validatePatch(patch []patchOp, snapshot map[string]interface{}) error {
	for i := range patch {
		switch patch[i].Op {
		case "add", "remove", "replace":
		default:
			return fmt.Errorf("op[%d]: unsupported operation", i)
		}
		segs, err := splitPointerPath(patch[i].Path)
		if err != nil {
			return fmt.Errorf("op[%d]: %s", i, err)
		}
		switch patch[i].Op {
		case "remove", "replace":
			if _, ok := resolveFull(snapshot, segs); !ok {
				return fmt.Errorf("op[%d]: %s path does not resolve into the snapshot", i, patch[i].Op)
			}
		case "add":
			if !parentIsObject(snapshot, segs) {
				return fmt.Errorf("op[%d]: add parent does not resolve into the snapshot", i)
			}
		}
	}
	return nil
}

// validateRunningSnapshot rejects an empty running snapshot. The server's
// own contract answers 400 to len(snapshot)==0 (platform/configaudit
// handlers.go:105), so a 200 empty-patch-for-empty-snapshot pair is
// unverifiable by definition. Object-ness is already enforced by the
// decoder in fetchRunningConfig.
func validateRunningSnapshot(running map[string]interface{}) error {
	if len(running) == 0 {
		return errors.New("running snapshot is empty")
	}
	return nil
}

// splitPointerPath splits an RFC 6901 JSON Pointer into its unescaped
// reference tokens. Splitting happens BEFORE unescaping (RFC 6901 section
// 4: split on "/", then unescape each token), so a literal "/" inside a
// key (escaped as "~1") can never inject a fake separator. Unescaping is
// strict left-to-right: only "~0" and "~1" are valid; any other "~x" or a
// trailing "~" is an error. The server's escapePointerSegment (diff.go
// 86-92, "~" first then "/") emits only "~0"/"~1", so every
// server-emitted segment passes and strict unescape is injective on
// emitted segments. "/" yields the single empty token "" — a legal
// emission for a snapshot holding the empty-string key (diff.go:57-58).
func splitPointerPath(path string) ([]string, error) {
	if path == "" || path[0] != '/' {
		return nil, errors.New(`path must be non-empty and start with "/"`)
	}
	raw := strings.Split(path[1:], "/")
	segs := make([]string, len(raw))
	for i, seg := range raw {
		var b strings.Builder
		b.Grow(len(seg))
		for j := 0; j < len(seg); j++ {
			if seg[j] != '~' {
				b.WriteByte(seg[j])
				continue
			}
			if j+1 >= len(seg) {
				return nil, errors.New("invalid RFC 6901 path")
			}
			switch seg[j+1] {
			case '0':
				b.WriteByte('~')
			case '1':
				b.WriteByte('/')
			default:
				return nil, errors.New("invalid RFC 6901 path")
			}
			j++
		}
		segs[i] = b.String()
	}
	return segs, nil
}

// resolveFull walks segs through snapshot, requiring every intermediate
// node to be a map[string]interface{} before descending. The leaf node
// may be any type: the server emits replace at map-valued leaves when the
// value type changed and remove for any leaf kind (diff.go:71-82), so
// existence is key presence (m[k], ok), never value shape. segs is never
// empty — splitPointerPath guarantees at least one token for any "/"-
// rooted path.
func resolveFull(snapshot map[string]interface{}, segs []string) (interface{}, bool) {
	cur := interface{}(snapshot)
	for i, seg := range segs {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil, false
		}
		v, ok := m[seg]
		if !ok {
			return nil, false
		}
		if i == len(segs)-1 {
			return v, true
		}
		cur = v
	}
	return nil, false
}

// parentIsObject walks all segments except the last, requiring each to
// resolve through an object, and requires the final parent node itself to
// be an object (the server recursed into it, diff.go:55-63). The added
// key itself may be present or absent — the acceptance is deliberately
// one-directional (see the B4-3 truthiness spec, D2). A single-segment
// path has the snapshot root as parent, which is always an object.
func parentIsObject(snapshot map[string]interface{}, segs []string) bool {
	if len(segs) == 1 {
		return true
	}
	cur := interface{}(snapshot)
	for _, seg := range segs[:len(segs)-1] {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return false
		}
		v, ok := m[seg]
		if !ok {
			return false
		}
		cur = v
	}
	_, ok := cur.(map[string]interface{})
	return ok
}
