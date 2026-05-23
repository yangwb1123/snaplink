package security

import "crypto/subtle"

// ConstantTimeStringEq wraps crypto/subtle.ConstantTimeCompare for
// strings — short-circuits on length mismatch (the standard library
// function does too, but the wrapper keeps the length check explicit
// at every call site so reviewers don't have to remember the
// guarantee). Returns 1 when equal, 0 otherwise.
func ConstantTimeStringEq(a, b string) int {
	if len(a) != len(b) {
		return 0
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b))
}
