package operations

import (
	"context"
	"strings"

	"github.com/yangwb1123/snaplink/shared/core"
)

// PaginatedOperationStore is an OPTIONAL extension a Store MAY implement to
// push ListOperations' pagination down into the backend instead of the
// grpcadmin fallback's full List() -> offset slice. Same optional-extension
// pattern as core.PaginatedClientStore: callers type-assert, absence
// degrades to List() (keeping today's store order).
//
// The extension path introduces a deterministic order — id ascending — where
// today's fallback response is store-order; the store-side contract is
// therefore pinned to ID, never creation/insertion order.
type PaginatedOperationStore interface {
	ListPage(ctx context.Context, q core.PageQuery) ([]Operation, []byte, int, error)
}

// CompareOperations orders two operations by ID (unique, so no tiebreaker
// is needed) — the extension path's deterministic id-ascending order.
func CompareOperations(a, b Operation) int {
	return strings.Compare(a.ID, b.ID)
}
