package memorystoreoauth

import "errors"

// ErrStoreAtCapacity is returned by Issue when the store's optional
// MaxEntries cap (0 = unbounded, the default) is set and already
// reached. Shared by MemoryRefreshTokenStore, MemoryDeviceCodeStore, and
// MemoryPARStore — see each store's MaxEntries doc comment. Every Issue
// caller already treats a non-nil Issue error as an ordinary operational
// failure (the oauth SPI's existing contract), so this needs no new
// caller-side handling.
var ErrStoreAtCapacity = errors.New("memorystoreoauth: store at capacity")
