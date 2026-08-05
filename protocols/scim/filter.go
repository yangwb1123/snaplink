package scim

import (
	"errors"
	"strconv"
	"strings"
)

// SCIM 2.0 filter support (RFC 7644 §3.4.2.2): a self-contained
// recursive-descent parser + evaluator powering GET /Users?filter= and
// GET /Groups?filter=, which Azure AD / Okta rely on to reconcile a single
// resource rather than paging the whole directory.
//
// Grammar (RFC 7644 §3.4.2.2 ABNF): or < and < not < grouping;
// attrExpr = attrPath pr | attrPath compareOp compValue |
// valuePath (attrPath "[" filter "]" [ "." subAttr ]) [ pr | compareOp compValue ];
// compareOp = eq/ne/co/sw/ew/gt/ge/lt/le. Value-path sub-filters parse as
// a full filter (a lenient superset of the restricted valFilter) and
// schema-URN-prefixed attribute paths resolve to their base attribute.
// Anything else is rejected as invalidFilter, never silently honored.
//
// PERFORMANCE: evaluation runs over a full List scan (acceptable at admin
// / directory-provisioning scale). An indexed lookup SPI
// (UserProvider.FindByAttribute) is a future optimization for SaaS-scale
// directories; the parser/evaluator here are its reusable front end.

// errInvalidFilter is the sentinel a malformed filter resolves to; the
// handler maps it to a SCIM 400 with scimType=invalidFilter (RFC 7644
// §3.4.2.2 / §3.12). All parse failures collapse to this sentinel so the
// wire response is uniform; the reason is intentionally not echoed.
var errInvalidFilter = errors.New("invalid SCIM filter")

// filterError returns the invalidFilter sentinel (one seam for attaching
// richer detail later).
func filterError(string) error { return errInvalidFilter }

// parseValuePath parses attrPath "[" filter "]" [ "." subAttr ] with the
// trailing pr / compareOp compValue; the bracketed filter is a lenient
// superset of the ABNF's restricted valFilter.
func (p *filterParser) parseValuePath(attr string) (filterExpr, error) {
	p.next() // consume '['
	subFilter, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	closeTok, ok := p.next()
	if !ok || closeTok.kind != tokRBracket {
		return nil, filterError("expected ']'")
	}
	subAttr := ""
	if t, ok := p.peek(); ok && t.kind == tokAttr {
		// The lexer emits the post-']' ".word" as a tokAttr.
		subAttr = t.text
		p.next()
	}
	opTok, ok := p.next()
	if !ok || opTok.kind != tokKeyword {
		return nil, filterError("expected a comparison operator after value-path")
	}
	if opTok.text == opPr {
		return valuePathNode{attr: attr, subFilter: subFilter, subAttr: subAttr}, nil
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
	switch opTok.text {
	case opCo, opSw, opEw:
		if valTok.lit.kind != litString {
			return nil, filterError(opTok.text + " requires a string value")
		}
	}
	return valuePathCompareNode{attr: attr, subFilter: subFilter, subAttr: subAttr, op: opTok.text, lit: valTok.lit}, nil
}

// maxFilterLen caps filter length before tokenizing (a real reconcile
// filter is a few hundred bytes; early rejection prevents memory-abuse
// amplification).
const maxFilterLen = 4096

// maxFilterDepth caps recursive-descent nesting so a crafted deeply-nested
// filter cannot overflow the goroutine stack.
const maxFilterDepth = 50

// logicalAnd/Or/Not are the lower-cased logical keywords (case-folded).
const (
	logicalAnd = "and"
	logicalOr  = "or"
	logicalNot = "not"
)

// Comparison operator keywords (RFC 7644 §3.4.2.2 Table 3), lower-cased.
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
	// match reports whether the resource described by view satisfies the
	// expression. view.resolve maps an attribute path (lower-cased) to its
	// value set; view.elements resolves multi-valued complex attributes
	// for value-path filters. See userAttrs / groupAttrs.
	match(view attrView) bool
}

// attrLookup resolves a lower-cased attribute path to its value(s): one
// element for a single-valued attribute, one per value for a multi-valued
// one (a comparison matches ANY value, RFC 7644 §3.4.2.2). present
// distinguishes an absent attribute from an empty one for "pr".
type attrLookup func(path string) (values []string, present bool)

// --- AST node types ---

// orNode / andNode / notNode are the logical combinators.
type orNode struct{ left, right filterExpr }

func (n orNode) match(v attrView) bool { return n.left.match(v) || n.right.match(v) }

// andNode is a logical AND of two sub-expressions.
type andNode struct{ left, right filterExpr }

func (n andNode) match(v attrView) bool { return n.left.match(v) && n.right.match(v) }

type notNode struct{ inner filterExpr }

func (n notNode) match(v attrView) bool { return !n.inner.match(v) }

// presentNode is the "attr pr" presence test.
type presentNode struct{ attr string }

func (n presentNode) match(v attrView) bool {
	vals, present := v.resolve(n.attr)
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

func (n compareNode) match(v attrView) bool {
	vals, present := v.resolve(n.attr)
	if !present {
		// Absent attribute: "ne" is true (the resource does NOT carry that
		// value — the Azure AD / Okta reconcile expectation), everything
		// else false.
		return n.op == opNe
	}
	// "ne" holds only when NO value equals the literal.
	if n.op == opNe {
		for _, v := range vals {
			if compareOne(v, opEq, n.lit) {
				return false // some value equals -> "ne" is false
			}
		}
		return true
	}
	// All other operators match if ANY value matches.
	for _, v := range vals {
		if compareOne(v, n.op, n.lit) {
			return true
		}
	}
	return false
}

// compareOne evaluates one scalar value against the literal under op.
// String comparisons fold case (RFC 7644 §3.4.2.2: non-caseExact
// attributes match case-insensitively); ordering ops compare numerically
// when both sides are numbers, else lexically.
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

// literalEquals implements "eq" against a typed literal (bool/null against
// the canonical form, strings folded, numbers numerically with a textual
// fallback).
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

// orderCompare implements gt/ge/lt/le: numeric when both sides parse,
// else lexical on the raw strings (SCIM defines no case folding for
// ordering operators).
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

// foldLower lower-cases for case-insensitive comparison (SCIM
// caseExact=false folding).
func foldLower(s string) string { return strings.ToLower(s) }

// parseFilter parses a SCIM filter string into an evaluable AST, or
// errInvalidFilter on any malformed input. An empty/whitespace-only filter
// reaching here is a client error (the handler treats an absent ?filter=
// as "no filter" before calling this).
func parseFilter(raw string) (filterExpr, error) {
	// Reject inputs that exceed the byte budget before touching the tokenizer.
	// This is the first line of defence against memory-amplification attacks.
	if len(raw) > maxFilterLen {
		return nil, filterError("filter exceeds maximum length")
	}
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

// filterParser is the recursive-descent cursor; depth tracks paren
// nesting against maxFilterDepth.
type filterParser struct {
	toks  []token
	pos   int
	depth int
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

// parseOr / parseAnd / parseNot / parsePrimary implement the precedence
// ladder (or < and < not < grouping).
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
		p.depth++
		if p.depth > maxFilterDepth {
			return nil, filterError("filter nesting depth exceeded")
		}
		inner, err := p.parseOr()
		p.depth--
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

func (p *filterParser) parsePrimary() (filterExpr, error) {
	t, ok := p.peek()
	if !ok {
		return nil, filterError("expected an expression")
	}
	if t.kind == tokLParen {
		p.next() // consume "("
		p.depth++
		if p.depth > maxFilterDepth {
			return nil, filterError("filter nesting depth exceeded")
		}
		inner, err := p.parseOr()
		p.depth--
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

func (p *filterParser) expectRParen() error {
	t, ok := p.next()
	if !ok || t.kind != tokRParen {
		return filterError("expected ')'")
	}
	return nil
}

// parseAttrExpr := attrPath "pr" | attrPath compareOp compValue |
// valuePath (attrPath "[" valFilter "]" [ "." subAttr ]) [ pr | compareOp compValue ]
func (p *filterParser) parseAttrExpr() (filterExpr, error) {
	attrTok, ok := p.next()
	if !ok || attrTok.kind != tokAttr {
		return nil, filterError("expected an attribute path")
	}
	if t, ok := p.peek(); ok && t.kind == tokLBracket {
		return p.parseValuePath(attrTok.text)
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
