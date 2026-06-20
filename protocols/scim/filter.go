package scim

import (
	"errors"
	"strconv"
	"strings"
)

// SCIM 2.0 filter support (RFC 7644 §3.4.2.2). This is a self-contained
// recursive-descent parser + evaluator for the COMMON connector subset of
// the SCIM filter grammar — no external dependency. It powers
// GET /Users?filter= and GET /Groups?filter=, which Azure AD / Okta rely
// on to reconcile a single resource (filter=userName eq "alice") rather
// than paging the whole directory.
//
// Grammar implemented (a subset of RFC 7644 §3.4.2.2 ABNF):
//
//	filter   = orExpr
//	orExpr   = andExpr  *( "or"  andExpr )
//	andExpr  = notExpr  *( "and" notExpr )
//	notExpr  = "not" "(" filter ")" / primary
//	primary  = "(" filter ")" / attrExpr
//	attrExpr = attrPath "pr" / attrPath compareOp compValue
//	compareOp= "eq" / "ne" / "co" / "sw" / "ew" / "gt" / "ge" / "lt" / "le"
//
// Operator precedence (lowest to highest): or < and < not < grouping —
// "and" binds tighter than "or" per the ABNF, so
// `a eq 1 or b eq 2 and c eq 3` parses as `a eq 1 or (b eq 2 and c eq 3)`.
//
// NOT implemented (rejected as invalidFilter, never silently honored):
// value-path filters ("emails[type eq \"work\"]"), the schema-URN-prefixed
// attribute form, and complex grouping inside an attribute path. These are
// uncommon for the provisioning reconcile path; surfacing them as
// invalidFilter lets a connector fall back rather than trust a wrong page.
//
// PERFORMANCE: evaluation runs over a full List scan (filter applied in
// the handler after List, before pagination). That is acceptable at admin
// / directory-provisioning scale (operator-defined user + group counts).
// An indexed lookup SPI (e.g. UserProvider.FindByAttribute) is a future
// optimization for SaaS-scale directories; the parser/evaluator here are
// the reusable front end for it.

// errInvalidFilter is the sentinel a malformed filter resolves to. The
// handler maps it to a SCIM 400 with scimType=invalidFilter (RFC 7644
// §3.4.2.2 / §3.12). All parse failures collapse to this one sentinel so
// the wire response is uniform; the textual reason is intentionally NOT
// echoed (connectors branch on scimType, not the detail, and the surface
// is admin-only so a position offset would only add noise).
var errInvalidFilter = errors.New("invalid SCIM filter")

// filterError returns the single invalidFilter sentinel. WHY a function
// rather than returning errInvalidFilter directly: it documents intent at
// each parse-failure site and leaves one seam to attach a richer detail
// later without touching every caller.
func filterError(string) error { return errInvalidFilter }

// logicalAnd / logicalOr / logicalNot are the lower-cased logical keywords
// (RFC 7644 §3.4.2.2). Keyword matching folds case ("AND" == "and").
const (
	logicalAnd = "and"
	logicalOr  = "or"
	logicalNot = "not"
)

// Comparison operator keywords (RFC 7644 §3.4.2.2 Table 3). Lower-cased;
// the tokenizer folds the inbound operator's case before comparing.
const (
	opEq = "eq" // equal
	opNe = "ne" // not equal
	opCo = "co" // contains
	opSw = "sw" // starts with
	opEw = "ew" // ends with
	opPr = "pr" // present (has a non-empty value)
	opGt = "gt" // greater than
	opGe = "ge" // greater than or equal
	opLt = "lt" // less than
	opLe = "le" // less than or equal
)

// filterExpr is a parsed filter AST node. Each evaluator type implements
// match; matchesFilter walks the tree against a resource's attribute view.
type filterExpr interface {
	// match reports whether the resource described by attrs satisfies the
	// expression. attrs resolves an attribute path (lower-cased) to its
	// value set; see resourceAttrs / groupAttrs.
	match(attrs attrLookup) bool
}

// attrLookup resolves a lower-cased SCIM attribute path to its value(s).
// A single-valued attribute returns one element; a multi-valued attribute
// (emails, members) returns one element per value so a comparison can
// match ANY value (RFC 7644 §3.4.2.2: a multi-valued attribute matches if
// any of its values matches). present reports whether the attribute is
// modeled and carries any value, distinguishing an absent attribute from
// an empty one for the "pr" operator.
type attrLookup func(path string) (values []string, present bool)

// --- AST node types ---

// orNode is a logical OR of two sub-expressions.
type orNode struct{ left, right filterExpr }

func (n orNode) match(a attrLookup) bool { return n.left.match(a) || n.right.match(a) }

// andNode is a logical AND of two sub-expressions.
type andNode struct{ left, right filterExpr }

func (n andNode) match(a attrLookup) bool { return n.left.match(a) && n.right.match(a) }

// notNode negates a parenthesized sub-expression.
type notNode struct{ inner filterExpr }

func (n notNode) match(a attrLookup) bool { return !n.inner.match(a) }

// presentNode is the "attr pr" presence test.
type presentNode struct{ attr string }

func (n presentNode) match(a attrLookup) bool {
	vals, present := a(n.attr)
	if !present {
		return false
	}
	// A present-but-empty value (e.g. userName "") does not satisfy pr:
	// RFC 7644 §3.4.2.2 defines pr as "matches if the attribute has a
	// non-empty or non-null value".
	for _, v := range vals {
		if v != "" {
			return true
		}
	}
	return false
}

// compareNode is a binary comparison "attr OP value".
type compareNode struct {
	attr string
	op   string
	// lit is the comparison literal, already typed by the tokenizer:
	// string / number / bool / null.
	lit literal
}

func (n compareNode) match(a attrLookup) bool {
	vals, present := a(n.attr)
	if !present {
		// An absent attribute never equals a value; "ne" against an absent
		// attribute is true (the resource does NOT carry that value). This
		// matches the Azure AD / Okta reconcile expectation that
		// `attr ne "x"` surfaces resources lacking the attribute.
		return n.op == opNe
	}
	// "ne" means "no value equals the literal", so it must hold for ALL
	// values of a multi-valued attribute — evaluate via the eq result.
	if n.op == opNe {
		for _, v := range vals {
			if compareOne(v, opEq, n.lit) {
				return false // some value equals -> "ne" is false
			}
		}
		return true
	}
	// All other operators match if ANY value matches (RFC 7644 §3.4.2.2).
	for _, v := range vals {
		if compareOne(v, n.op, n.lit) {
			return true
		}
	}
	return false
}

// compareOne evaluates one scalar value against the literal under op.
// String comparisons fold case (the attributes this slice models —
// userName, displayName, emails, name.*, externalId, members — are not
// caseExact, and RFC 7644 §3.4.2.2 specifies case-insensitive matching for
// non-caseExact string attributes). Ordering ops (gt/ge/lt/le) compare
// numerically when both sides are numbers, else lexically.
func compareOne(value, op string, lit literal) bool {
	switch op {
	case opEq:
		return literalEquals(value, lit)
	case opCo:
		return strings.Contains(foldLower(value), foldLower(lit.str))
	case opSw:
		return strings.HasPrefix(foldLower(value), foldLower(lit.str))
	case opEw:
		return strings.HasSuffix(foldLower(value), foldLower(lit.str))
	case opGt, opGe, opLt, opLe:
		return orderCompare(value, op, lit)
	}
	return false
}

// literalEquals implements "eq" against a typed literal. Boolean and null
// literals compare against the value's canonical form; strings fold case;
// numbers compare numerically (so `1` eq `1.0`) with a textual fallback.
func literalEquals(value string, lit literal) bool {
	switch lit.kind {
	case litBool:
		// active is the only modeled boolean; its stored form is the
		// canonical "true"/"false" string.
		return foldLower(value) == lit.str
	case litNull:
		return value == ""
	case litNumber:
		if a, errA := strconv.ParseFloat(value, 64); errA == nil {
			if b, errB := strconv.ParseFloat(lit.str, 64); errB == nil {
				return a == b
			}
		}
		return value == lit.str
	default: // litString
		return foldLower(value) == foldLower(lit.str)
	}
}

// orderCompare implements gt/ge/lt/le. Numbers compare numerically when
// both sides parse; otherwise the comparison is lexical on the raw strings
// (SCIM does not define case folding for the ordering operators).
func orderCompare(value, op string, lit literal) bool {
	if lit.kind == litNumber {
		if a, errA := strconv.ParseFloat(value, 64); errA == nil {
			if b, errB := strconv.ParseFloat(lit.str, 64); errB == nil {
				return numOrder(a, b, op)
			}
		}
	}
	return strOrder(strings.Compare(value, lit.str), op)
}

func numOrder(a, b float64, op string) bool {
	switch op {
	case opGt:
		return a > b
	case opGe:
		return a >= b
	case opLt:
		return a < b
	case opLe:
		return a <= b
	}
	return false
}

func strOrder(cmp int, op string) bool {
	switch op {
	case opGt:
		return cmp > 0
	case opGe:
		return cmp >= 0
	case opLt:
		return cmp < 0
	case opLe:
		return cmp <= 0
	}
	return false
}

// foldLower lower-cases s for case-insensitive string comparison. Pulled
// out so the intent (SCIM caseExact=false folding) reads at each call site.
func foldLower(s string) string { return strings.ToLower(s) }

// parseFilter parses a SCIM filter string into an evaluable AST, or
// errInvalidFilter on any malformed input. An empty/whitespace-only filter
// reaching here is a client error (the handler treats an absent ?filter=
// as "no filter" before calling this).
func parseFilter(raw string) (filterExpr, error) {
	toks, err := tokenizeFilter(raw)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return nil, filterError("empty filter")
	}
	p := &filterParser{toks: toks}
	expr, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	// Trailing tokens after a complete expression (e.g. a dangling operand
	// or an unbalanced paren) are a malformed filter.
	if !p.atEnd() {
		return nil, filterError("unexpected trailing tokens")
	}
	return expr, nil
}

// filterParser is the recursive-descent cursor over the token stream.
type filterParser struct {
	toks []token
	pos  int
}

func (p *filterParser) atEnd() bool { return p.pos >= len(p.toks) }

func (p *filterParser) peek() (token, bool) {
	if p.atEnd() {
		return token{}, false
	}
	return p.toks[p.pos], true
}

func (p *filterParser) next() (token, bool) {
	t, ok := p.peek()
	if ok {
		p.pos++
	}
	return t, ok
}

// parseOr := parseAnd ( "or" parseAnd )*
func (p *filterParser) parseOr() (filterExpr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.kind != tokKeyword || t.text != logicalOr {
			return left, nil
		}
		p.next() // consume "or"
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = orNode{left: left, right: right}
	}
}

// parseAnd := parseNot ( "and" parseNot )*
func (p *filterParser) parseAnd() (filterExpr, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.kind != tokKeyword || t.text != logicalAnd {
			return left, nil
		}
		p.next() // consume "and"
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = andNode{left: left, right: right}
	}
}

// parseNot := "not" "(" parseOr ")" | parsePrimary
func (p *filterParser) parseNot() (filterExpr, error) {
	t, ok := p.peek()
	if ok && t.kind == tokKeyword && t.text == logicalNot {
		p.next() // consume "not"
		// "not" MUST be followed by a parenthesized group (RFC 7644
		// §3.4.2.2: `not ( <filter> )`), never a bare attribute expression.
		open, ok := p.next()
		if !ok || open.kind != tokLParen {
			return nil, filterError("not must be followed by '('")
		}
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if err := p.expectRParen(); err != nil {
			return nil, err
		}
		return notNode{inner: inner}, nil
	}
	return p.parsePrimary()
}

// parsePrimary := "(" parseOr ")" | attrExpr
func (p *filterParser) parsePrimary() (filterExpr, error) {
	t, ok := p.peek()
	if !ok {
		return nil, filterError("expected an expression")
	}
	if t.kind == tokLParen {
		p.next() // consume "("
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if err := p.expectRParen(); err != nil {
			return nil, err
		}
		return inner, nil
	}
	return p.parseAttrExpr()
}

// expectRParen consumes a required ")", erroring on anything else.
func (p *filterParser) expectRParen() error {
	t, ok := p.next()
	if !ok || t.kind != tokRParen {
		return filterError("expected ')'")
	}
	return nil
}

// parseAttrExpr := attrPath "pr" | attrPath compareOp compValue
func (p *filterParser) parseAttrExpr() (filterExpr, error) {
	attrTok, ok := p.next()
	if !ok || attrTok.kind != tokAttr {
		return nil, filterError("expected an attribute path")
	}
	opTok, ok := p.next()
	if !ok || opTok.kind != tokKeyword {
		return nil, filterError("expected a comparison operator after attribute")
	}
	if opTok.text == opPr {
		return presentNode{attr: attrTok.text}, nil
	}
	switch opTok.text {
	case opEq, opNe, opCo, opSw, opEw, opGt, opGe, opLt, opLe:
	default:
		return nil, filterError("unknown operator: " + opTok.text)
	}
	valTok, ok := p.next()
	if !ok || valTok.kind != tokValue {
		return nil, filterError("expected a value after operator")
	}
	// co/sw/ew are string-only operators (RFC 7644 §3.4.2.2): a non-string
	// literal (number/bool/null) is a malformed filter, not a never-match.
	switch opTok.text {
	case opCo, opSw, opEw:
		if valTok.lit.kind != litString {
			return nil, filterError(opTok.text + " requires a string value")
		}
	}
	return compareNode{attr: attrTok.text, op: opTok.text, lit: valTok.lit}, nil
}
