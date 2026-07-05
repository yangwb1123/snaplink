package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
)

// Bundle holds translations keyed first by locale tag (matching a bundle
// JSON file's base name, e.g. "en", "es"), then by message key. A flat
// key -> per-locale-string map is sufficient for the SSO server's narrow
// localization surface (error responses) — there is no pluralization or
// ICU-message engine here, and none is needed for short, static strings.
type Bundle map[string]map[string]string

// MemoryLocalizer is the reference Localizer: bundles held entirely in
// memory (loaded once via LoadBundles/NewDefaultLocalizer, or built
// directly with NewMemoryLocalizer for tests / programmatic bundles). No
// I/O on the lookup path — the same "load once, serve from memory" shape
// as every other Memory* SPI implementation in this SDK.
type MemoryLocalizer struct {
	bundle        Bundle
	defaultLocale string
}

var _ Localizer = (*MemoryLocalizer)(nil)

// NewMemoryLocalizer builds a Localizer over bundle, falling back to
// defaultLocale (e.g. "en") when a requested locale — and its base
// language — have no entry. bundle is used directly, not copied; treat
// it as immutable once passed in.
func NewMemoryLocalizer(bundle Bundle, defaultLocale string) *MemoryLocalizer {
	return &MemoryLocalizer{bundle: bundle, defaultLocale: defaultLocale}
}

// Localize implements Localizer: exact locale -> locale's base language
// -> exact default locale -> default locale's base language -> not
// found. Each step is one map lookup, so a full miss costs at most four.
func (m *MemoryLocalizer) Localize(key, locale string) (string, bool) {
	if v, ok := m.lookupLocaleAndBase(key, locale); ok {
		return v, true
	}
	if locale == m.defaultLocale {
		return "", false
	}
	return m.lookupLocaleAndBase(key, m.defaultLocale)
}

// lookupLocaleAndBase tries the exact locale, then its base language
// (the subtag before the first '-'), skipping the second lookup when
// they're identical (a bare "es" has no distinct base to retry).
func (m *MemoryLocalizer) lookupLocaleAndBase(key, locale string) (string, bool) {
	if v, ok := m.lookup(locale, key); ok {
		return v, true
	}
	if base := baseLanguage(locale); base != strings.ToLower(locale) {
		return m.lookup(base, key)
	}
	return "", false
}

func (m *MemoryLocalizer) lookup(locale, key string) (string, bool) {
	if locale == "" {
		return "", false
	}
	messages, ok := m.bundle[strings.ToLower(locale)]
	if !ok {
		return "", false
	}
	v, ok := messages[key]
	return v, ok
}

// baseLanguage returns the lower-cased primary language subtag of a
// BCP 47 tag ("es-MX" -> "es"; "es" -> "es") so bundle keys can be plain
// lowercase locale tags regardless of the request's casing.
func baseLanguage(locale string) string {
	locale = strings.ToLower(locale)
	if i := strings.IndexByte(locale, '-'); i >= 0 {
		return locale[:i]
	}
	return locale
}

//go:embed bundles/*.json
var demoBundles embed.FS

// LoadBundles reads every *.json file in fsys's root as one locale's
// message map — a file's base name without extension becomes the locale
// tag ("es.json" -> "es"). Each file must be a flat JSON object of
// key -> string; anything else is a load error (fail loud at startup,
// not at first lookup). Use this to load an operator's own, larger
// catalog: LoadBundles(os.DirFS("./translations")) or
// fs.Sub(myEmbedFS, "translations").
func LoadBundles(fsys fs.FS) (Bundle, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("i18n: read bundle dir: %w", err)
	}
	out := make(Bundle, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		messages, err := loadBundleFile(fsys, e.Name())
		if err != nil {
			return nil, err
		}
		out[strings.ToLower(strings.TrimSuffix(e.Name(), ".json"))] = messages
	}
	return out, nil
}

func loadBundleFile(fsys fs.FS, name string) (map[string]string, error) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, fmt.Errorf("i18n: read %s: %w", name, err)
	}
	var messages map[string]string
	if err := json.Unmarshal(data, &messages); err != nil {
		return nil, fmt.Errorf("i18n: parse %s: %w", name, err)
	}
	return messages, nil
}

// NewDefaultLocalizer builds a MemoryLocalizer from the small
// demonstration bundle shipped in bundles/ — en + es translations for a
// handful of the most common oracle-safe error codes (see
// docs/error-codes.md). It exists to prove the mechanism end-to-end
// without requiring every operator to hand-author a bundle before trying
// WithLocalizer. Production deployments with a larger catalog should call
// LoadBundles over their OWN fs.FS and NewMemoryLocalizer directly,
// rather than growing this demo bundle in place.
func NewDefaultLocalizer(defaultLocale string) (*MemoryLocalizer, error) {
	sub, err := fs.Sub(demoBundles, "bundles")
	if err != nil {
		return nil, fmt.Errorf("i18n: sub bundles fs: %w", err)
	}
	bundle, err := LoadBundles(sub)
	if err != nil {
		return nil, err
	}
	return NewMemoryLocalizer(bundle, defaultLocale), nil
}
