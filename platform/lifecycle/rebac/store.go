package rebac

import "context"

// RelationTupleStore persists relationship tuples. Implementations MUST be
// safe for concurrent use and MUST validate on Write (see Tuple.Validate),
// mirroring conditionalaccess.Store and permissions.Provider's contract.
//
// Write and Delete are both idempotent: writing an already-stored tuple, or
// deleting one that was never stored (or already removed), is a silent
// no-op success — matching Zanzibar's set semantics (a tuple either exists
// once or not at all; there is no count/duplicate concept).
type RelationTupleStore interface {
	// Write upserts t into the tuple set, after Validate. Idempotent.
	Write(ctx context.Context, t Tuple) error
	// Delete removes t from the tuple set. Idempotent.
	Delete(ctx context.Context, t Tuple) error
	// Read returns every stored tuple matching filter (unspecified order).
	// Engine.Check calls Read with Object+Relation set to enumerate a
	// relation's grants; an admin/debug caller may pass a sparser filter
	// (e.g. Subject only) to answer "what does this subject have access
	// to", though that reverse query is O(n) on the Memory reference
	// store (see memory.go).
	Read(ctx context.Context, filter TupleFilter) ([]Tuple, error)
	// ApplyBatch validates every mutation before atomically applying the
	// complete set. No tuple may change when validation or persistence fails.
	ApplyBatch(ctx context.Context, writes, deletes []Tuple) error
}
