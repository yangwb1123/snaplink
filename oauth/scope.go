package oauth

import "strings"

// JoinScope joins a slice of scopes back into the space-delimited
// wire format used by the scope query parameter (RFC 6749 §3.3).
func JoinScope(scopes []string) string {
	return strings.Join(scopes, " ")
}

// SplitScope parses a space-delimited scope string into a slice,
// returning nil for empty input so the AuthCode / DeviceCode entry's
// Scopes field stays nil-not-empty (cleaner reflection / JSON marshal).
func SplitScope(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, " ")
}
