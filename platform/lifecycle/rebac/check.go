package rebac

import "context"

// Engine resolves Check queries against a wired RelationTupleStore. It holds
// no state of its own beyond the store reference, so it is cheap to
// construct and safe to share across goroutines (the store it delegates to
// is required to be concurrency-safe).
type Engine struct {
	store RelationTupleStore
}

// NewEngine wraps store. A nil store is accepted (Check then always returns
// ErrNoStore, fail-closed) so a caller can wire an Engine before its backing
// store is ready without a nil-pointer panic.
func NewEngine(store RelationTupleStore) *Engine {
	return &Engine{store: store}
}

// Check reports whether subject has relation on object: a direct tuple
// (object, relation, subject), OR one level of group-membership indirection
// — a tuple (object, relation, "G#R") whose referenced userset (G, R)
// directly contains subject. See the package doc for the exact semantics
// and what is deliberately NOT walked (nested groups, wildcard subjects,
// full userset-rewrite rules).
//
// Fail-closed: a nil Engine, an unwired store, or a store error all return
// (false, err) — never a bare false that a caller could mistake for a
// deliberate "no access" answer versus "the check could not be evaluated".
func (e *Engine) Check(ctx context.Context, object, relation, subject string) (bool, error) {
	if e == nil || e.store == nil {
		return false, ErrNoStore
	}
	direct, err := e.store.Read(ctx, TupleFilter{Object: object, Relation: relation})
	if err != nil {
		return false, err
	}
	if tuplesContainSubject(direct, subject) {
		return true, nil
	}
	return e.checkUsersetIndirection(ctx, direct, subject)
}

// checkUsersetIndirection expands, one level, every userset-reference
// Subject found among direct (the tuples already read for object+relation),
// looking for subject as a DIRECT member. It deliberately does not expand a
// member that is itself a userset reference — that would be nested-group
// support, explicitly out of scope (see package doc).
func (e *Engine) checkUsersetIndirection(ctx context.Context, direct []Tuple, subject string) (bool, error) {
	for _, t := range direct {
		usersetObj, usersetRel, ok := SplitUserset(t.Subject)
		if !ok {
			continue
		}
		members, err := e.store.Read(ctx, TupleFilter{Object: usersetObj, Relation: usersetRel})
		if err != nil {
			return false, err
		}
		if tuplesContainSubject(members, subject) {
			return true, nil
		}
	}
	return false, nil
}

// tuplesContainSubject reports whether any tuple's Subject is exactly
// subject (a direct-membership match; no userset expansion).
func tuplesContainSubject(tuples []Tuple, subject string) bool {
	for _, t := range tuples {
		if t.Subject == subject {
			return true
		}
	}
	return false
}
