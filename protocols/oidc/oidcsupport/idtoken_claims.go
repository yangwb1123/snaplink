package oidcsupport

import (
	"encoding/json"

	"github.com/yangwb1123/snaplink/shared/core"
)

// ProjectIDTokenClaims filters the extra claims map to only include
// claims the RP requested via the OIDC Core §5.5 `claims` parameter.
// When requestedClaims is empty or parsing fails, the full map is
// returned unchanged (backward compatible).
//
// Call this before building IDTokenRequest.Claims so the id_token
// only carries what the RP asked for — shrinking id_token size and
// respecting the client's declared claim preferences.
func ProjectIDTokenClaims(claims map[string]string, requestedClaims json.RawMessage) map[string]string {
	if len(claims) == 0 || len(requestedClaims) == 0 {
		return claims
	}
	idTokReq, _, err := core.ParseRequestedClaims(requestedClaims)
	if err != nil || len(idTokReq) == 0 {
		return claims
	}
	result := make(map[string]string, len(idTokReq))
	for k, v := range claims {
		if _, requested := idTokReq[k]; requested {
			result[k] = v
		}
	}
	return result
}
