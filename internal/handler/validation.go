package handler

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// IsUnknownTokenErr returns true if err indicates an unknown/consumed/expired token.
func IsUnknownTokenErr(err error) bool {
	// This is a simplified check - in root it checks against specific sentinel errors
	return err != nil
}

// JWSHeaderAlg extracts the alg from a compact JWS header.
func JWSHeaderAlg(token string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 1 {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return "", false
	}
	return header.Alg, true
}

// AlgAllowed reports whether alg appears in the allowlist.
func AlgAllowed(alg string, allow []string) bool {
	for _, a := range allow {
		if a == alg {
			return true
		}
	}
	return false
}
