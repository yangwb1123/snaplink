package scim

import (
	"strconv"
	"strings"
	"unicode"
)

// SCIM filter tokenizer (RFC 7644 §3.4.2.2). Splits a filter string into
// the token stream the recursive-descent parser in filter.go consumes.
// Hand-written (no regexp / external dep) so the grammar stays explicit
// and the value-literal rules (quoted strings with escapes, numbers,
// true/false/null) match the SCIM JSON value production exactly.

// tokenKind enumerates the lexical categories.
type tokenKind int

const (
	tokKeyword  tokenKind = iota // logical (and/or/not) or comparison (eq/.../pr) word
	tokAttr                      // an attribute path (e.g. userName, name.familyName)
	tokValue                     // a typed literal (string/number/bool/null)
	tokLParen                    // (
	tokRParen                    // )
	tokLBracket                  // [ (value-path opener)
	tokRBracket                  // ] (value-path closer)
)

// literalKind types a value literal so the evaluator picks the right
// comparison semantics without re-parsing the text.
type literalKind int

const (
	litString literalKind = iota
	litNumber
	litBool
	litNull
)

// literal is a typed comparison value. str holds the canonical textual
// form: the unquoted/unescaped string for litString, the numeric text for
// litNumber, "true"/"false" for litBool, "null" for litNull. The evaluator
// derives numeric/bool meaning from str on demand.
type literal struct {
	kind literalKind
	str  string
}

// token is one lexical unit. text is the lower-cased keyword/operator (for
// tokKeyword) or the raw attribute path lower-cased (for tokAttr); lit is
// populated only for tokValue.
type token struct {
	kind tokenKind
	text string
	lit  literal
}

// keywordSet is the set of bareword tokens that are operators/logicals
// rather than attribute paths. A bareword NOT in this set is an attribute
// path (tokAttr); the bool/null literals are handled separately in the
// value reader, but appear here too because they can only ever be values,
// never attributes, and must not be mistaken for an attribute path.
var keywordSet = map[string]tokenKind{
	logicalAnd: tokKeyword,
	logicalOr:  tokKeyword,
	logicalNot: tokKeyword,
	opEq:       tokKeyword,
	opNe:       tokKeyword,
	opCo:       tokKeyword,
	opSw:       tokKeyword,
	opEw:       tokKeyword,
	opPr:       tokKeyword,
	opGt:       tokKeyword,
	opGe:       tokKeyword,
	opLt:       tokKeyword,
	opLe:       tokKeyword,
}

// literalWords maps the bareword value literals to their typed form. These
// are matched case-insensitively (RFC 7644 §3.4.2.2 references the JSON
// value production, and SCIM keywords are case-insensitive).
var literalWords = map[string]literal{
	"true":  {kind: litBool, str: "true"},
	"false": {kind: litBool, str: "false"},
	"null":  {kind: litNull, str: "null"},
}

// tokenizeFilter scans raw into a token slice, or errInvalidFilter on a
// lexical error (unterminated string, stray character, malformed number).
func tokenizeFilter(raw string) ([]token, error) {
	var toks []token
	rs := []rune(raw)
	i := 0
	n := len(rs)
	var handled bool
	for i < n {
		c := rs[i]
		switch {
		case unicode.IsSpace(c):
			i++

		case c == '"':
			s, next, err := readString(rs, i)
			if err != nil {
				return nil, err
			}
			toks = append(toks, token{kind: tokValue, lit: literal{kind: litString, str: s}})
			i = next
		case c == '-' || (c >= '0' && c <= '9'):
			num, next, err := readNumber(rs, i)
			if err != nil {
				return nil, err
			}
			toks = append(toks, token{kind: tokValue, lit: literal{kind: litNumber, str: num}})
			i = next
		case isWordStart(c):
			word, next := readWord(rs, i)
			i = next
			toks = append(toks, classifyWord(word))
		default:
			if toks, i, handled = lexBracket(rs, toks, c, i); handled {
				continue
			}
			return nil, filterError("unexpected character in filter")
		}
	}
	return toks, nil
}

// lexBracket handles the grouping/bracket runes ('(', ')', '[', ']'),
// returning handled=true when c was consumed (including the value-path
// sub-attribute after ']'). Kept out of the main switch so the tokenizer's
// complexity stays within budget.
func lexBracket(rs []rune, toks []token, c rune, i int) ([]token, int, bool) {
	toks = append(toks, token{kind: bracketKind(c)})
	i++
	// A value-path sub-attribute (emails[...].value) lexes as a tokAttr
	// after the closer.
	if c == ']' {
		if sub, next := lexSubAttrAfterDot(rs, i); sub != nil {
			toks = append(toks, *sub)
			i = next
		}
	}
	return toks, i, true
}

// bracketKind maps a grouping/bracket rune to its token kind.
func bracketKind(c rune) tokenKind {
	switch c {
	case '(':
		return tokLParen
	case ')':
		return tokRParen
	case '[':
		return tokLBracket
	default:
		return tokRBracket
	}
}

// lexSubAttrAfterDot consumes the ".subAttr" that follows a value-path
// closer (emails[...].value). Returns nil when the next rune is not a
// dot; a bare '.' with no word is left for the main loop to reject as an
// unexpected character.
func lexSubAttrAfterDot(rs []rune, i int) (*token, int) {
	if i >= len(rs) || rs[i] != '.' {
		return nil, i
	}
	i++
	word, next := readWord(rs, i)
	if word == "" {
		return nil, i
	}
	return &token{kind: tokAttr, text: strings.ToLower(word)}, next
}

// classifyWord turns a bareword into the right token: a logical/comparison
// keyword, a bool/null literal, or otherwise an attribute path. Keywords
// and bool/null literals fold case; an attribute path is lower-cased so
// the evaluator's attrLookup (also lower-cased) matches case-insensitively
// (RFC 7643 §2.1 — attribute names are case-insensitive).
func classifyWord(word string) token {
	lower := strings.ToLower(word)
	if _, ok := keywordSet[lower]; ok {
		return token{kind: tokKeyword, text: lower}
	}
	if lit, ok := literalWords[lower]; ok {
		return token{kind: tokValue, lit: lit}
	}
	// Schema-URN-prefixed attribute (RFC 7643 §2.1 URN form): the
	// attribute is everything after the LAST ':' — the schema part is a
	// namespace, not part of the path the evaluator resolves.
	if idx := strings.LastIndex(lower, ":"); idx >= 0 && strings.HasPrefix(lower, "urn:") {
		lower = lower[idx+1:]
	}
	return token{kind: tokAttr, text: lower}
}

// isWordStart reports whether c can begin an attribute path or keyword.
// SCIM attribute names start with a letter (RFC 7643 §2.1 ABNF: ALPHA
// followed by name chars); we also admit '_' defensively though core
// attribute names don't use it.
func isWordStart(c rune) bool {
	return unicode.IsLetter(c) || c == '_'
}

// isWordChar reports whether c can continue an attribute path. Beyond
// letters/digits it admits '.' (sub-attribute separator, e.g.
// name.familyName), '-' and '_' (RFC 7643 name chars), and ':' so a
// schema-URN-prefixed attribute
// (urn:ietf:params:scim:schemas:core:2.0:User:userName) lexes; the prefix
// is stripped in classifyWord. '[' and ']' are their own tokens.
func isWordChar(c rune) bool {
	return unicode.IsLetter(c) || unicode.IsDigit(c) || c == '.' || c == '-' || c == '_' || c == ':'
}

// readWord consumes a bareword starting at i, returning it and the next
// index.
func readWord(rs []rune, i int) (string, int) {
	start := i
	for i < len(rs) && isWordChar(rs[i]) {
		i++
	}
	return string(rs[start:i]), i
}

// readString consumes a double-quoted SCIM string literal starting at the
// opening quote at index i, honoring JSON-style backslash escapes
// (RFC 7644 §3.4.2.2 strings follow the JSON string production). Returns
// the unescaped value and the index past the closing quote, or
// errInvalidFilter on an unterminated string or an invalid escape.
func readString(rs []rune, i int) (string, int, error) {
	var b strings.Builder
	i++ // skip opening quote
	for i < len(rs) {
		c := rs[i]
		switch c {
		case '"':
			return b.String(), i + 1, nil
		case '\\':
			next, err := writeStringEscape(&b, rs, i)
			if err != nil {
				return "", 0, err
			}
			i = next
		default:
			b.WriteRune(c)
			i++
		}
	}
	return "", 0, filterError("unterminated string")
}

// writeStringEscape decodes the backslash escape beginning at the backslash at
// index i, writes the decoded rune(s) to b, and returns the index just past the
// escape. Invalid/truncated escapes return errInvalidFilter (RFC 7644 §3.4.2.2
// strings follow the JSON string production).
func writeStringEscape(b *strings.Builder, rs []rune, i int) (int, error) {
	i++ // skip backslash
	if i >= len(rs) {
		return 0, filterError("unterminated escape in string")
	}
	switch esc := rs[i]; esc {
	case '"', '\\', '/':
		b.WriteRune(esc)
	case 'b':
		b.WriteRune('\b')
	case 'f':
		b.WriteRune('\f')
	case 'n':
		b.WriteRune('\n')
	case 'r':
		b.WriteRune('\r')
	case 't':
		b.WriteRune('\t')
	case 'u':
		// \uXXXX: four hex digits -> rune.
		if i+4 >= len(rs) {
			return 0, filterError("truncated \\u escape")
		}
		cp, err := strconv.ParseUint(string(rs[i+1:i+5]), 16, 32)
		if err != nil {
			return 0, filterError("invalid \\u escape")
		}
		b.WriteRune(rune(cp))
		i += 4
	default:
		return 0, filterError("invalid escape in string")
	}
	return i + 1, nil
}

// readNumber consumes a JSON-style number starting at i. It accepts an
// optional leading '-', integer digits, an optional fraction, and an
// optional exponent, then validates the whole token with strconv so a
// malformed number (e.g. "1.2.3", "-", "1e") is reported as
// errInvalidFilter rather than truncated.
func readNumber(rs []rune, i int) (string, int, error) {
	start := i
	if i < len(rs) && rs[i] == '-' {
		i++
	}
	i = skipDigits(rs, i)
	if i < len(rs) && rs[i] == '.' {
		i = skipDigits(rs, i+1)
	}
	i = skipExponent(rs, i)
	num := string(rs[start:i])
	if _, err := strconv.ParseFloat(num, 64); err != nil {
		return "", 0, filterError("malformed number")
	}
	return num, i, nil
}

// skipDigits advances past a run of ASCII digits starting at i, returning the
// index of the first non-digit (or len(rs)).
func skipDigits(rs []rune, i int) int {
	for i < len(rs) && rs[i] >= '0' && rs[i] <= '9' {
		i++
	}
	return i
}

// skipExponent advances past an optional JSON number exponent ([eE][+-]?digits)
// starting at i. With no exponent at i it returns i unchanged; strconv later
// rejects a degenerate exponent (e.g. "1e") as a malformed number.
func skipExponent(rs []rune, i int) int {
	if i >= len(rs) || (rs[i] != 'e' && rs[i] != 'E') {
		return i
	}
	i++
	if i < len(rs) && (rs[i] == '+' || rs[i] == '-') {
		i++
	}
	return skipDigits(rs, i)
}
