package webhook

import (
	"crypto/rand"
	"encoding/hex"
)

// newID returns a random hex identifier, mirroring auditspi.NewEventID —
// used to mint subscription and dead-letter-entry ids.
func newID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
