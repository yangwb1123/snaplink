package auditgovernance

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

const maxSourcePrefixBytes = 64

// TenantSourceID derives the pre-registered Audit Governance source for one
// tenant. The digest keeps source IDs fixed-size and prevents tenant text from
// becoming an authorization input or leaking through the event envelope.
func TenantSourceID(prefix, tenantID string) (string, error) {
	if !validSourcePrefix(prefix) || tenantID == "" || tenantID != strings.TrimSpace(tenantID) {
		return "", ErrInvalidConfig
	}
	digest := sha256.Sum256([]byte(tenantID))
	return prefix + "." + base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func validSourcePrefix(prefix string) bool {
	if prefix == "" || len(prefix) > maxSourcePrefixBytes || prefix != strings.TrimSpace(prefix) {
		return false
	}
	for index := range len(prefix) {
		value := prefix[index]
		if isSourceAlphaNumeric(value) || value == '.' || value == '_' || value == '-' {
			continue
		}
		return false
	}
	return isSourceAlphaNumeric(prefix[0]) && isSourceAlphaNumeric(prefix[len(prefix)-1])
}

func isSourceAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}
