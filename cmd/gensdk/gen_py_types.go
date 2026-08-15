package main

import (
	"fmt"
	"strings"
)

func pyMethodParams(op Operation) string {
	var required, optional []string
	for _, p := range op.PathParams {
		required = append(required, p.Name+": str")
	}
	bodyType := "Dict[str, Any]"
	if op.BodyType != nil {
		bodyType = pyType(op.BodyType)
	}
	if op.HasBody {
		if op.BodyRequired {
			required = append(required, "body: "+bodyType)
		} else {
			optional = append(optional, "body: Optional["+bodyType+"] = None")
		}
	}
	if len(op.QueryParams) > 0 {
		optional = append(optional, "query: Optional[Dict[str, Any]] = None")
	}
	parts := append([]string{"self"}, required...)
	parts = append(parts, optional...)
	return strings.Join(parts, ", ")
}

// pyPathExpr renders path as a Python f-string, substituting each
// {name} with urllib.parse.quote(name) — OpenAPI parameter names are
// already snake_case, so no identifier translation is needed (unlike
// tsPathExpr's camelCase conversion).
//
// Scans the ORIGINAL path with a forward-only cursor rather than
// mutate-and-rescan — see tsPathExpr's doc for why re-scanning the
// growing output (which contains the f-string's OWN "{"/"}" syntax)
// would never terminate.
func pyPathExpr(path string) string {
	if !strings.Contains(path, "{") {
		return fmt.Sprintf("%q", path)
	}
	var b strings.Builder
	b.WriteString(`f"`)
	i := 0
	for i < len(path) {
		start := strings.IndexByte(path[i:], '{')
		if start < 0 {
			b.WriteString(path[i:])
			break
		}
		start += i
		end := strings.IndexByte(path[start:], '}')
		if end < 0 {
			b.WriteString(path[i:])
			break
		}
		end += start
		b.WriteString(path[i:start])
		name := path[start+1 : end]
		b.WriteString("{urllib.parse.quote(" + name + ")}")
		i = end + 1
	}
	b.WriteByte('"')
	return b.String()
}

// pySnakeCase converts a camelCase operationId (e.g. "postToken") to
// snake_case ("post_token") for a PEP 8-idiomatic method name. Treats a
// run of uppercase letters as one acronym (e.g. "getJWKS" -> "get_jwks",
// "getClientByID" -> "get_client_by_id") rather than splitting every
// letter — a simple heuristic, not an acronym dictionary; see the
// package doc.
func pySnakeCase(s string) string {
	var b strings.Builder
	runes := []rune(s)
	for i, r := range runes {
		if isUpper(r) {
			prevLower := i > 0 && isLower(runes[i-1])
			nextLower := i+1 < len(runes) && isLower(runes[i+1])
			boundary := prevLower || (nextLower && i > 0 && isUpper(runes[i-1]))
			if i > 0 && boundary {
				b.WriteByte('_')
			}
			b.WriteRune(toLower(r))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isUpper(r rune) bool { return r >= 'A' && r <= 'Z' }
func isLower(r rune) bool { return r >= 'a' && r <= 'z' }
func toLower(r rune) rune {
	if isUpper(r) {
		return r + ('a' - 'A')
	}
	return r
}

// pySafe makes a description/summary line safe to place inside a
// `"""..."""` docstring.
func pySafe(s string) string {
	return strings.ReplaceAll(s, `"""`, "'''")
}

// pyType renders a TypeSpec as a Python type hint. nil (no response
// body) renders as "None".
func pyType(t *TypeSpec) string {
	if t == nil {
		return "None"
	}
	switch t.Kind {
	case KindString:
		return "str" // enum values are simplified to str; see README
	case KindInteger:
		return "int"
	case KindNumber:
		return "float"
	case KindBoolean:
		return "bool"
	case KindArray:
		return "List[" + pyType(t.Elem) + "]"
	case KindMap:
		return "Dict[str, " + pyType(t.Elem) + "]"
	case KindRef:
		return t.Name
	case KindUnion:
		return pyUnion(t.Variants)
	case KindObject:
		return "Dict[str, Any]" // named-field object with no $ref: no synthesized TypedDict, see README
	default:
		return "Any"
	}
}

func pyUnion(variants []*TypeSpec) string {
	seen := map[string]bool{}
	var parts []string
	for _, v := range variants {
		s := pyType(v)
		if !seen[s] {
			seen[s] = true
			parts = append(parts, s)
		}
	}
	switch len(parts) {
	case 0:
		return "Any"
	case 1:
		return parts[0]
	default:
		return "Union[" + strings.Join(parts, ", ") + "]"
	}
}

// pyEmitNamedType renders one components.schemas entry as a `TypedDict`
// subclass (object with named fields), a `List[...]` type alias (a
// top-level array schema, e.g. MenuTree), or a plain type-alias
// assignment for anything else (map/union/primitive).
//
// total=False on every generated TypedDict is a deliberate simplification:
// it makes every key optional to the type checker rather than encoding
// this generator's `required` list precisely (which would need
// Required[]/NotRequired[] — Python 3.11+ — or a two-class split; see
// README). At runtime TypedDict enforces nothing either way.
func pyEmitNamedType(b *strings.Builder, name string, t *TypeSpec) {
	switch {
	case t.Kind == KindArray:
		fmt.Fprintf(b, "%s = List[%s]\n\n\n", name, pyType(t.Elem))
	case t.Kind == KindObject && len(t.Fields) > 0:
		fmt.Fprintf(b, "class %s(TypedDict, total=False):\n", name)
		if t.Doc != "" {
			fmt.Fprintf(b, "    \"\"\"%s\"\"\"\n", pySafe(t.Doc))
		}
		for _, f := range t.Fields {
			fmt.Fprintf(b, "    %s: %s", pyFieldName(f.Name), pyType(f.Type))
			if f.Doc != "" {
				fmt.Fprintf(b, "  # %s", pySafe(f.Doc))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n\n")
	default:
		fmt.Fprintf(b, "%s = %s\n\n\n", name, pyType(t))
	}
}
