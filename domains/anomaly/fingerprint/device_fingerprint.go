// Package fingerprint provides deterministic device fingerprint extraction
// from stable HTTP client attributes (User-Agent, Accept-Language, etc.).
//
// The fingerprint is a SHA-256 hash that survives IP rotation, NAT, and
// browser restarts — suitable for "has this device been seen before?" checks
// without cookies or localStorage.
package fingerprint

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
)

// Input gathers the stable HTTP-surface attributes that contribute to the
// device fingerprint. Every field is optional — missing fields are simply
// omitted from the hash input.
type Input struct {
	UserAgent       string
	AcceptLanguage  string
	SecCHUA         string
	SecCHUAPlatform string
	SecCHUAMobile   string
	ColorDepth      string
	Timezone        string
}

// Derive computes a hex-encoded SHA-256 hash of the concatenated, sorted
// attribute key-value pairs. The sort ensures deterministic output regardless
// of field assignment order. A nil or zero-valued input returns empty string.
func Derive(in *Input) string {
	if in == nil {
		return ""
	}

	pairs := make([]string, 0, 7)
	if v := normalize(in.UserAgent); v != "" {
		pairs = append(pairs, "ua="+v)
	}
	if v := normalize(in.AcceptLanguage); v != "" {
		pairs = append(pairs, "al="+v)
	}
	if v := normalize(in.SecCHUA); v != "" {
		pairs = append(pairs, "chua="+v)
	}
	if v := normalize(in.SecCHUAPlatform); v != "" {
		pairs = append(pairs, "chuap="+v)
	}
	if v := normalize(in.SecCHUAMobile); v != "" {
		pairs = append(pairs, "chuam="+v)
	}
	if v := normalize(in.ColorDepth); v != "" {
		pairs = append(pairs, "cd="+v)
	}
	if v := normalize(in.Timezone); v != "" {
		pairs = append(pairs, "tz="+v)
	}

	if len(pairs) == 0 {
		return ""
	}

	sort.Strings(pairs)
	input := strings.Join(pairs, "&")
	h := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", h)
}

func normalize(s string) string {
	return strings.TrimSpace(strings.ToLower(s))
}
