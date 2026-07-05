package i18n

import (
	"sort"
	"strconv"
	"strings"
)

// acceptLangTag is one parsed Accept-Language entry: a language range
// plus its quality value.
type acceptLangTag struct {
	tag string
	q   float64
}

// topAcceptLanguageTag returns the highest-quality, first-listed-on-tie
// tag from an Accept-Language header value, e.g.
// "fr-CH, fr;q=0.9, en;q=0.8, *;q=0.5". Wildcard ("*") entries are
// skipped — they name no localizable tag. A malformed or missing q
// parameter defaults to 1.0 (permissive parsing: better to rank a
// slightly-malformed entry than drop the whole header).
func topAcceptLanguageTag(header string) string {
	if header == "" {
		return ""
	}
	tags := parseAcceptLanguageTags(header)
	if len(tags) == 0 {
		return ""
	}
	sort.SliceStable(tags, func(i, j int) bool { return tags[i].q > tags[j].q })
	return tags[0].tag
}

// parseAcceptLanguageTags splits + parses every non-wildcard entry.
func parseAcceptLanguageTags(header string) []acceptLangTag {
	parts := strings.Split(header, ",")
	tags := make([]acceptLangTag, 0, len(parts))
	for _, p := range parts {
		if tag, q, ok := parseAcceptLanguageEntry(p); ok {
			tags = append(tags, acceptLangTag{tag: tag, q: q})
		}
	}
	return tags
}

// parseAcceptLanguageEntry parses one comma-separated Accept-Language
// entry ("fr;q=0.9") into its tag + quality value. ok=false for an empty
// or wildcard-only entry.
func parseAcceptLanguageEntry(entry string) (tag string, q float64, ok bool) {
	entry = strings.TrimSpace(entry)
	if entry == "" || entry == "*" {
		return "", 0, false
	}
	tag, q = entry, 1.0
	if i := strings.IndexByte(entry, ';'); i >= 0 {
		tag = strings.TrimSpace(entry[:i])
		if qv, qok := parseQValue(entry[i+1:]); qok {
			q = qv
		}
	}
	if tag == "" || tag == "*" {
		return "", 0, false
	}
	return tag, q, true
}

// parseQValue extracts the numeric value out of a ";q=0.8"-shaped
// parameter. ok=false (caller defaults to q=1.0) for anything that
// isn't exactly that shape.
func parseQValue(param string) (float64, bool) {
	param = strings.TrimSpace(param)
	if !strings.HasPrefix(param, "q=") && !strings.HasPrefix(param, "Q=") {
		return 0, false
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(param[2:]), 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
