package configaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Digest returns a stable sha256 hex digest of v (typically a config
// snapshot map[string]any). The cross-replica drift-detection loop
// broadcasts only this digest over the cluster Bus, never the (possibly
// large, secret-bearing) snapshot itself.
//
// Stability: encoding/json.Marshal sorts map[string]any keys before
// writing them out, so two structurally identical maps always marshal to
// the same byte sequence regardless of Go's randomized map iteration order
// — no separate canonicalization pass is needed here.
func Digest(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
