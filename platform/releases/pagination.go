package releases

import (
	"context"
	"strings"

	"github.com/yangwb1123/snaplink/shared/core"
)

// PaginatedReleaseStore is an OPTIONAL extension a ReleaseStore MAY
// implement to push List's pagination down into the backend instead of the
// grpcadmin fallback's full List() -> sort -> offset slice. Same
// optional-extension pattern as core.PaginatedClientStore: callers
// type-assert, absence degrades to List(). Releases sort by ID only (the
// proto exposes no order_by/filter).
type PaginatedReleaseStore interface {
	ListPage(ctx context.Context, q core.PageQuery) ([]*Release, []byte, int, error)
}

// CompareReleases orders two releases by ID (unique, so no tiebreaker is
// needed) — the fixed sort both the fallback path and the memory-store
// ListPage use.
func CompareReleases(a, b *Release) int {
	return strings.Compare(a.ID, b.ID)
}
