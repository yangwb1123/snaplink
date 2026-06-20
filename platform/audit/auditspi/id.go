package auditspi

import (
	"crypto/rand"
	"encoding/hex"
)

// NewEventID returns a random hex event ID. Sinks assign it to Event.ID when
// the caller did not set one; shared here so every sink backend (in this
// package's consumers) mints IDs identically.
func NewEventID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
