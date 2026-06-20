package core

import "encoding/json"

// CloneRawJSON returns a copy of the raw JSON bytes — guards against aliasing
// when the same authorization_details / claims blob is held across
// request-scoped and persistence-scoped lifetimes. Nil-safe.
//
// Lives in core (the leaf) so both oauth and oidc can clone RAR/claims blobs
// without oidc importing oauth (oauth.CloneRawJSON delegates here).
func CloneRawJSON(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	out := make(json.RawMessage, len(raw))
	copy(out, raw)
	return out
}
