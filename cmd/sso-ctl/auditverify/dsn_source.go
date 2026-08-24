package auditverify

import (
	"context"
	"fmt"

	"github.com/yangwb1123/snaplink/cmd/auditstore"
	"github.com/yangwb1123/snaplink/platform/audit"
)

// readFromStore is the --dsn source: it opens the durable audit store
// (sqlite or postgres, chosen by the shared dialect classifier) read-only
// and pages it newest-first, returning events in CHAIN ORDER plus whether
// the --limit cap truncated the chain. It mirrors readFromURL's paging
// discipline exactly; the opener (auditstore.OpenReadOnly) never migrates
// and fails closed on a schema-version mismatch, so a store whose schema
// does not match the binary is reported (exit 1), never migrated, never
// guessed.
func readFromStore(dsn string, limit, pageSize int) ([]*audit.Event, bool, error) {
	st, err := auditstore.OpenReadOnly(dsn)
	if err != nil {
		return nil, false, fmt.Errorf("open audit store %q: %w", dsn, err)
	}
	defer func() { _ = st.Close() }()
	return auditstore.ReadChain(context.Background(), st, limit, pageSize)
}
