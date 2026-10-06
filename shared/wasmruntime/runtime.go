// Package wasmruntime coordinates wazero runtime construction across policy hosts.
package wasmruntime

import (
	"context"
	"sync"

	"github.com/tetratelabs/wazero"
)

var constructionMu sync.Mutex

// New creates a runtime without racing wazero's process-wide version cache.
// Wazero v1.12.0 writes that cache without synchronization during compiler
// construction. The lock must be shared by authentication and authorization
// hosts; per-host locks would still race when both are initialized together.
// Compilation and guest execution remain concurrent and use the caller's
// unchanged runtime configuration.
func New(ctx context.Context, config wazero.RuntimeConfig) wazero.Runtime {
	constructionMu.Lock()
	defer constructionMu.Unlock()
	return wazero.NewRuntimeWithConfig(ctx, config)
}
