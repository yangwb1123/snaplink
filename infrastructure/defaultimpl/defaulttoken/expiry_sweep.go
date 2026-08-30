package defaulttoken

import (
	"sync"
	"time"
)

const sweepInterval = time.Minute

// sweepExpired removes only entries that expired before now. An entry expiring
// exactly at now is still live for this sweep and is reclaimed on the next
// one, preserving the strict expiry boundary.
func sweepExpired(m *sync.Map, now time.Time, expires func(any) time.Time) {
	m.Range(func(key, value any) bool {
		if expires(value).Before(now) {
			m.Delete(key)
		}
		return true
	})
}
