package rebac

import (
	"errors"
	"strings"
)

// Sentinel errors returned by Tuple.Validate and the Store implementations.
var (
	// ErrInvalidTuple is returned when a Tuple fails Validate: an empty
	// field, or an Object/concrete-Subject that isn't "namespace:id"
	// shaped, or a Relation containing a reserved character.
	ErrInvalidTuple = errors.New("rebac: invalid tuple")
	// ErrNoStore is returned by Engine.Check when no RelationTupleStore is
	// wired. Fail-closed (see package doc): a nil store answers with an
	// error, never a silent false-as-deny that could be mistaken for a
	// deliberate policy decision.
	ErrNoStore = errors.New("rebac: no store wired")
)

// Tuple is one Zanzibar-style relationship fact: subject has relation on
// object. Object is always "namespace:id" (e.g. "document:42"). Subject is
// either a concrete principal in the same "namespace:id" shape (e.g.
// "user:alice") or a userset reference "namespace:id#relation" (e.g.
// "group:eng#member") — see [SplitUserset]. Relation is a bare identifier
// ("viewer", "editor", "member") with no reserved characters.
type Tuple struct {
	Object   string `json:"object"`
	Relation string `json:"relation"`
	Subject  string `json:"subject"`
}

// Validate rejects a structurally malformed Tuple: any empty field, an
// Object or concrete Subject not in "namespace:id" shape, a Relation
// containing ':' or '#', or a userset Subject whose referenced relation
// segment is empty ("group:eng#"). Store implementations validate on Write
// so malformed tuples never enter the graph Engine.Check walks.
func (t Tuple) Validate() error {
	if err := validateRef(t.Object); err != nil {
		return err
	}
	if err := validateRelation(t.Relation); err != nil {
		return err
	}
	if usersetObj, usersetRel, ok := SplitUserset(t.Subject); ok {
		if err := validateRef(usersetObj); err != nil {
			return err
		}
		return validateRelation(usersetRel)
	}
	return validateRef(t.Subject)
}

// validateRef requires the "namespace:id" shape: a non-empty segment before
// the first ':' and a non-empty segment after it.
func validateRef(ref string) error {
	i := strings.IndexByte(ref, ':')
	if i <= 0 || i == len(ref)-1 {
		return ErrInvalidTuple
	}
	return nil
}

// validateRelation rejects an empty relation or one carrying a character
// reserved for the tuple wire shapes ('#' introduces a userset reference,
// ':' separates namespace from id).
func validateRelation(relation string) error {
	if relation == "" || strings.ContainsAny(relation, ":#") {
		return ErrInvalidTuple
	}
	return nil
}

// SplitUserset reports whether subject is a userset reference — the
// Zanzibar "namespace:id#relation" shape meaning "anyone who has `relation`
// on `namespace:id`" — splitting it into the referenced object and
// relation. ok is false for a concrete subject (no '#'), e.g. "user:alice".
func SplitUserset(subject string) (object, relation string, ok bool) {
	i := strings.IndexByte(subject, '#')
	if i < 0 {
		return "", "", false
	}
	return subject[:i], subject[i+1:], true
}

// TupleFilter narrows a Read call. A zero-value field matches ANY tuple on
// that dimension; a TupleFilter{} (all zero) matches every stored tuple.
type TupleFilter struct {
	Object   string
	Relation string
	Subject  string
}

// matches reports whether t satisfies every non-empty field of f.
func (f TupleFilter) matches(t Tuple) bool {
	if f.Object != "" && f.Object != t.Object {
		return false
	}
	if f.Relation != "" && f.Relation != t.Relation {
		return false
	}
	if f.Subject != "" && f.Subject != t.Subject {
		return false
	}
	return true
}
