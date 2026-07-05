package i18n

import "testing"

func TestPreferredLocale_AcceptLanguageWins(t *testing.T) {
	t.Parallel()
	got := PreferredLocale("fr-CH, fr;q=0.9, en;q=0.8", "de-DE")
	if got != "fr-CH" {
		t.Errorf("PreferredLocale = %q, want fr-CH (highest q, first-listed)", got)
	}
}

func TestPreferredLocale_QualityOrdering(t *testing.T) {
	t.Parallel()
	got := PreferredLocale("en;q=0.5, es;q=0.9", "")
	if got != "es" {
		t.Errorf("PreferredLocale = %q, want es (higher q wins over first-listed)", got)
	}
}

func TestPreferredLocale_WildcardSkipped(t *testing.T) {
	t.Parallel()
	got := PreferredLocale("*;q=0.8, pt-BR;q=0.5", "")
	if got != "pt-BR" {
		t.Errorf("PreferredLocale = %q, want pt-BR (wildcard carries no locale)", got)
	}
}

func TestPreferredLocale_MalformedQDefaultsToOne(t *testing.T) {
	t.Parallel()
	got := PreferredLocale("en;q=bogus, es;q=0.5", "")
	if got != "en" {
		t.Errorf("PreferredLocale = %q, want en (malformed q defaults to 1.0)", got)
	}
}

func TestPreferredLocale_EmptyHeaderFallsBackToGeo(t *testing.T) {
	t.Parallel()
	got := PreferredLocale("", "ja-JP")
	if got != "ja-JP" {
		t.Errorf("PreferredLocale = %q, want geo fallback ja-JP", got)
	}
}

func TestPreferredLocale_BothEmpty(t *testing.T) {
	t.Parallel()
	if got := PreferredLocale("", ""); got != "" {
		t.Errorf("PreferredLocale = %q, want empty", got)
	}
}

func TestPreferredLocale_OnlyWildcardFallsBackToGeo(t *testing.T) {
	t.Parallel()
	got := PreferredLocale("*", "ko-KR")
	if got != "ko-KR" {
		t.Errorf("PreferredLocale = %q, want geo fallback ko-KR (Accept-Language was wildcard-only)", got)
	}
}
