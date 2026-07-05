// Package i18n provides translation support for the small set of
// user-facing strings the SSO server renders itself — today, just the
// optional localized error_description on error responses. It is
// intentionally narrow: this SDK is a token-issuing backend, not a UI
// renderer, so there is no page templating here, just message-key ->
// localized-string resolution behind a small interface any operator can
// swap (a bigger JSON/YAML catalog, a TMS-backed fetcher, gettext, etc).
//
// # Relationship to platform/geo's recommended_language
//
// platform/geo already resolves a per-request "recommended_language" UX
// hint (core.GeoInfo.RecommendedLanguage), surfaced on the /auth/login
// response so a client can render its OWN UI in the user's likely
// language. This package answers a different, narrower question — "what
// is the localized string for message key K in locale L" — for strings
// the SERVER itself emits (error bodies). PreferredLocale deliberately
// does not recompute a recommendation: it prefers the request's
// Accept-Language header and otherwise takes whatever geo (or another
// caller) already resolved, so the two features share one signal instead
// of drifting into competing answers for "what language is this user".
//
// # Opt-in
//
// Nothing in this package runs unless a Localizer is wired (see
// interfaces/sso's WithLocalizer) — an unconfigured server never reads
// Accept-Language for this purpose and never adds a wire field.
package i18n

// Localizer resolves a message key to a localized string for a requested
// BCP 47 locale tag (RFC 5646, e.g. "en", "en-US", "es-MX"), falling back
// to the implementation's own configured default locale when the
// requested tag — and its base language — have no bundle entry.
//
// Implementations MUST be safe for concurrent use: Localize runs on the
// request hot path for every enriched error response.
type Localizer interface {
	// Localize returns the localized string for key in locale, and
	// whether a translation was found. ok=false means neither locale,
	// its base language, nor the implementation's default locale (nor
	// ITS base language) has an entry for key — the caller keeps
	// whatever untranslated response it already had; Localize never
	// invents a message.
	Localize(key, locale string) (value string, ok bool)
}

// PreferredLocale picks the single candidate locale tag to hand to
// Localizer.Localize: the highest-quality tag from an Accept-Language
// header value (RFC 9110 §12.5.4) when present, otherwise geoRecommended
// — normally platform/geo's already-resolved recommended_language for
// this same request (see package doc). Returns "" when neither signal is
// available; callers pass that straight through and rely on the
// Localizer's own default-locale fallback.
//
// This is not a full RFC 4647 language-range negotiation against the
// bundle's supported locales — Localize already walks exact -> base
// language -> default locale on its own, so a single top candidate plus
// that fallback chain covers the realistic inputs (a browser's
// Accept-Language, or geo's one recommendation) without pulling a
// negotiation engine into the shared kernel.
func PreferredLocale(acceptLanguage, geoRecommended string) string {
	if tag := topAcceptLanguageTag(acceptLanguage); tag != "" {
		return tag
	}
	return geoRecommended
}
