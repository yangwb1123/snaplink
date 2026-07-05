package i18n

import (
	"testing"
	"testing/fstest"
)

func testBundle() Bundle {
	return Bundle{
		"en": {"invalid_credentials": "bad credentials (en)"},
		"es": {"invalid_credentials": "credenciales inválidas (es)"},
		"fr": {"invalid_credentials": "identifiants invalides (fr)"},
	}
}

func TestMemoryLocalizer_ExactMatch(t *testing.T) {
	t.Parallel()
	loc := NewMemoryLocalizer(testBundle(), "en")
	v, ok := loc.Localize("invalid_credentials", "es")
	if !ok || v != "credenciales inválidas (es)" {
		t.Fatalf("Localize(es) = %q, %v", v, ok)
	}
}

func TestMemoryLocalizer_BaseLanguageFallback(t *testing.T) {
	t.Parallel()
	loc := NewMemoryLocalizer(testBundle(), "en")
	// "es-MX" has no direct bundle entry; falls back to "es".
	v, ok := loc.Localize("invalid_credentials", "es-MX")
	if !ok || v != "credenciales inválidas (es)" {
		t.Fatalf("Localize(es-MX) = %q, %v, want base-language fallback to es", v, ok)
	}
}

func TestMemoryLocalizer_DefaultLocaleFallback(t *testing.T) {
	t.Parallel()
	loc := NewMemoryLocalizer(testBundle(), "en")
	// "de" (German) isn't in the bundle at all; falls back to the default "en".
	v, ok := loc.Localize("invalid_credentials", "de")
	if !ok || v != "bad credentials (en)" {
		t.Fatalf("Localize(de) = %q, %v, want default-locale fallback to en", v, ok)
	}
}

func TestMemoryLocalizer_UnknownKeyNotFound(t *testing.T) {
	t.Parallel()
	loc := NewMemoryLocalizer(testBundle(), "en")
	v, ok := loc.Localize("no_such_key", "en")
	if ok || v != "" {
		t.Fatalf("Localize(unknown key) = %q, %v, want not found", v, ok)
	}
}

func TestMemoryLocalizer_CaseInsensitiveLocale(t *testing.T) {
	t.Parallel()
	loc := NewMemoryLocalizer(testBundle(), "en")
	v, ok := loc.Localize("invalid_credentials", "ES-MX")
	if !ok || v != "credenciales inválidas (es)" {
		t.Fatalf("Localize(ES-MX) = %q, %v, want case-insensitive base-language match", v, ok)
	}
}

func TestMemoryLocalizer_EmptyLocaleUsesDefault(t *testing.T) {
	t.Parallel()
	loc := NewMemoryLocalizer(testBundle(), "en")
	v, ok := loc.Localize("invalid_credentials", "")
	if !ok || v != "bad credentials (en)" {
		t.Fatalf("Localize(\"\") = %q, %v, want default locale en", v, ok)
	}
}

func TestMemoryLocalizer_NoDefaultConfigured(t *testing.T) {
	t.Parallel()
	loc := NewMemoryLocalizer(Bundle{"en": {"k": "v"}}, "")
	if v, ok := loc.Localize("k", "de"); ok || v != "" {
		t.Fatalf("Localize with no matching locale and no default = %q, %v, want not found", v, ok)
	}
}

func TestNewDefaultLocalizer_DemoBundleResolves(t *testing.T) {
	t.Parallel()
	loc, err := NewDefaultLocalizer("en")
	if err != nil {
		t.Fatalf("NewDefaultLocalizer: %v", err)
	}
	for _, key := range []string{"invalid_credentials", "invalid_request", "account_locked", "mfa_invalid", "email_not_verified"} {
		if _, ok := loc.Localize(key, "en"); !ok {
			t.Errorf("demo en bundle missing key %q", key)
		}
		if _, ok := loc.Localize(key, "es"); !ok {
			t.Errorf("demo es bundle missing key %q", key)
		}
	}
	// A locale entirely absent from the demo bundle falls back to the
	// configured default rather than reporting not-found.
	v, ok := loc.Localize("invalid_credentials", "de-DE")
	if !ok || v == "" {
		t.Errorf("Localize(de-DE) = %q, %v, want default-locale fallback", v, ok)
	}
}

func TestLoadBundles_MalformedJSONErrors(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{
		"broken.json": &fstest.MapFile{Data: []byte("{not valid json")},
	}
	if _, err := LoadBundles(fsys); err == nil {
		t.Fatal("LoadBundles: expected error for malformed bundle JSON, got nil")
	}
}

func TestLoadBundles_SkipsNonJSONAndNestedDirs(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{
		"en.json":       &fstest.MapFile{Data: []byte(`{"k":"v"}`)},
		"README.md":     &fstest.MapFile{Data: []byte("not a bundle")},
		"sub/ignore.go": &fstest.MapFile{Data: []byte("package sub")},
	}
	b, err := LoadBundles(fsys)
	if err != nil {
		t.Fatalf("LoadBundles: %v", err)
	}
	if len(b) != 1 || b["en"]["k"] != "v" {
		t.Fatalf("LoadBundles = %#v, want only en.json parsed", b)
	}
}
