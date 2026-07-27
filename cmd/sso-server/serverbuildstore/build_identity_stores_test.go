package serverbuildstore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yangwb1123/snaplink/config"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/security"
	"github.com/yangwb1123/snaplink/shared/security/peertrust"
	"github.com/yangwb1123/snaplink/shared/spi"
)

func testLogger() spi.Logger { return spi.NopLogger{} }

func TestConvertClientJWKs_NilAndEmpty(t *testing.T) {
	t.Parallel()
	if got := ConvertClientJWKs(nil); got != nil {
		t.Errorf("nil input: got %v, want nil", got)
	}
	if got := ConvertClientJWKs([]config.ClientJWK{}); got != nil {
		t.Errorf("empty input: got %v, want nil", got)
	}
}

// TestConvertClientJWKs_CopiesEveryField proves every wire field survives the
// config.ClientJWK -> sso.JWK transform; a dropped field would silently
// corrupt a client's registered JWKS.
func TestConvertClientJWKs_CopiesEveryField(t *testing.T) {
	t.Parallel()
	in := []config.ClientJWK{{
		Kty: "RSA", Use: "sig", Alg: "RS256", Kid: "k1",
		Crv: "", X: "x-val", N: "n-val", E: "AQAB",
	}}
	got := ConvertClientJWKs(in)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	want := sso.JWK{Kty: "RSA", Use: "sig", Alg: "RS256", Kid: "k1", X: "x-val", N: "n-val", E: "AQAB"}
	if got[0] != want {
		t.Errorf("got %+v, want %+v", got[0], want)
	}
}

func TestBuildClientCertExtractor_DefaultIsTLSPeer(t *testing.T) {
	t.Parallel()
	for _, backend := range []string{"", "tls", "peer"} {
		ex, mode, err := BuildClientCertExtractor(config.MTLSConfig{Enabled: true, Backend: backend}, nil)
		if err != nil {
			t.Fatalf("backend=%q: %v", backend, err)
		}
		if ex == nil {
			t.Fatalf("backend=%q: nil extractor", backend)
		}
		if mode == "" {
			t.Errorf("backend=%q: empty mode label", backend)
		}
	}
}

func TestBuildClientCertExtractor_HeaderRequiresName(t *testing.T) {
	t.Parallel()
	_, _, err := BuildClientCertExtractor(config.MTLSConfig{Enabled: true, Backend: "header"}, nil)
	if err == nil {
		t.Fatal("expected error: header backend without header.name")
	}
}

func TestBuildClientCertExtractor_HeaderOK(t *testing.T) {
	t.Parallel()
	ex, mode, err := BuildClientCertExtractor(config.MTLSConfig{
		Enabled: true,
		Backend: "proxy", // alias for "header"
		Header:  config.MTLSHeaderConfig{Name: "X-SSL-Client-Cert", Encoding: "pem"},
	}, nil)
	if err != nil {
		t.Fatalf("BuildClientCertExtractor: %v", err)
	}
	if ex == nil {
		t.Fatal("nil extractor")
	}
	if _, ok := ex.(*security.HeaderClientCertExtractor); !ok {
		t.Errorf("extractor type = %T, want *security.HeaderClientCertExtractor", ex)
	}
	if mode == "" {
		t.Error("empty mode label")
	}
}

func TestBuildClientCertExtractor_UnknownBackend(t *testing.T) {
	t.Parallel()
	if _, _, err := BuildClientCertExtractor(config.MTLSConfig{Enabled: true, Backend: "bogus"}, nil); err == nil {
		t.Fatal("expected error: unknown backend")
	}
}

func TestParseHeaderCertEncoding_Valid(t *testing.T) {
	t.Parallel()
	cases := map[string]security.HeaderCertEncoding{
		"":           security.HeaderCertEncodingURLPEM,
		"url-pem":    security.HeaderCertEncodingURLPEM,
		"URLPEM":     security.HeaderCertEncodingURLPEM,
		"url_pem":    security.HeaderCertEncodingURLPEM,
		"pem":        security.HeaderCertEncodingPEM,
		"PEM":        security.HeaderCertEncodingPEM,
		"base64-der": security.HeaderCertEncodingBase64DER,
		"base64der":  security.HeaderCertEncodingBase64DER,
		"base64_der": security.HeaderCertEncodingBase64DER,
	}
	for in, want := range cases {
		got, err := ParseHeaderCertEncoding(in)
		if err != nil {
			t.Errorf("in=%q: unexpected error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("in=%q: got %v, want %v", in, got, want)
		}
	}
}

func TestParseHeaderCertEncoding_Invalid(t *testing.T) {
	t.Parallel()
	if _, err := ParseHeaderCertEncoding("rot13"); err == nil {
		t.Fatal("expected error for unrecognized encoding")
	}
}

func TestBuildDPoPNonceProvider_NoKeyFileGeneratesProcessLocal(t *testing.T) {
	t.Parallel()
	p, err := BuildDPoPNonceProvider(config.DPoPNonceConfig{}, testLogger())
	if err != nil {
		t.Fatalf("BuildDPoPNonceProvider: %v", err)
	}
	if p == nil {
		t.Fatal("nil provider")
	}
}

func TestBuildDPoPNonceProvider_MissingKeyFile(t *testing.T) {
	t.Parallel()
	_, err := BuildDPoPNonceProvider(config.DPoPNonceConfig{KeyFile: "/no/such/file"}, testLogger())
	if err == nil {
		t.Fatal("expected error reading missing key file")
	}
}

func TestBuildDPoPNonceProvider_HexKeyFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "nonce.key")
	// 32 hex chars = 16 raw bytes, the minimum this loader accepts.
	if err := os.WriteFile(path, []byte("00112233445566778899aabbccddeeff\n"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	p, err := BuildDPoPNonceProvider(config.DPoPNonceConfig{KeyFile: path}, testLogger())
	if err != nil {
		t.Fatalf("BuildDPoPNonceProvider: %v", err)
	}
	if p == nil {
		t.Fatal("nil provider")
	}
}

func TestBuildClientStore_MemoryAndUnknownBackend(t *testing.T) {
	t.Parallel()
	store, err := BuildClientStore(config.IdentityConfig{}, nil, postgresbackend.Dialect(""))
	if err != nil || store == nil {
		t.Fatalf("memory: store=%v err=%v", store, err)
	}
	if _, err := BuildClientStore(config.IdentityConfig{Backend: "carrier-pigeon"}, nil, postgresbackend.Dialect("")); err == nil {
		t.Fatal("expected error: unknown backend")
	}
}

func TestBuildDeviceSecretStore_DisabledMemoryUnknown(t *testing.T) {
	t.Parallel()
	if s, err := BuildDeviceSecretStore(config.NativeSSOConfig{}, nil, postgresbackend.Dialect("")); err != nil || s != nil {
		t.Fatalf("disabled: store=%v err=%v, want (nil, nil)", s, err)
	}
	if s, err := BuildDeviceSecretStore(config.NativeSSOConfig{Backend: "memory"}, nil, postgresbackend.Dialect("")); err != nil || s == nil {
		t.Fatalf("memory: store=%v err=%v", s, err)
	}
	if _, err := BuildDeviceSecretStore(config.NativeSSOConfig{Backend: "carrier-pigeon"}, nil, postgresbackend.Dialect("")); err == nil {
		t.Fatal("expected error: unknown backend")
	}
}

func TestBuildPasswordResetStore_DisabledMemoryRedisUnknown(t *testing.T) {
	t.Parallel()
	if s, err := BuildPasswordResetStore(config.PasswordResetConfig{}, nil); err != nil || s != nil {
		t.Fatalf("disabled: store=%v err=%v, want (nil, nil)", s, err)
	}
	if s, err := BuildPasswordResetStore(config.PasswordResetConfig{Backend: "memory"}, nil); err != nil || s == nil {
		t.Fatalf("memory: store=%v err=%v", s, err)
	}
	// redis backend with no shared client wired must fail loud, not
	// nil-pointer-panic through to the redis backend constructor.
	if _, err := BuildPasswordResetStore(config.PasswordResetConfig{Backend: "redis"}, nil); err == nil {
		t.Fatal("expected error: redis backend without a redis client")
	}
	if _, err := BuildPasswordResetStore(config.PasswordResetConfig{Backend: "carrier-pigeon"}, nil); err == nil {
		t.Fatal("expected error: unknown backend")
	}
}

func TestBuildConsentStore_DisabledMemoryUnknown(t *testing.T) {
	t.Parallel()
	if s, err := BuildConsentStore(config.SelfServiceStoreConfig{}, nil, postgresbackend.Dialect("")); err != nil || s != nil {
		t.Fatalf("disabled: store=%v err=%v, want (nil, nil)", s, err)
	}
	if s, err := BuildConsentStore(config.SelfServiceStoreConfig{Backend: "memory"}, nil, postgresbackend.Dialect("")); err != nil || s == nil {
		t.Fatalf("memory: store=%v err=%v", s, err)
	}
	if _, err := BuildConsentStore(config.SelfServiceStoreConfig{Backend: "carrier-pigeon"}, nil, postgresbackend.Dialect("")); err == nil {
		t.Fatal("expected error: unknown backend")
	}
}

func TestBuildPasswordCredentialStore_DisabledMemoryUnknown(t *testing.T) {
	t.Parallel()
	if s, err := BuildPasswordCredentialStore(config.SelfServiceStoreConfig{}, nil, postgresbackend.Dialect("")); err != nil || s != nil {
		t.Fatalf("disabled: store=%v err=%v, want (nil, nil)", s, err)
	}
	if s, err := BuildPasswordCredentialStore(config.SelfServiceStoreConfig{Backend: "memory"}, nil, postgresbackend.Dialect("")); err != nil || s == nil {
		t.Fatalf("memory: store=%v err=%v", s, err)
	}
	if _, err := BuildPasswordCredentialStore(config.SelfServiceStoreConfig{Backend: "carrier-pigeon"}, nil, postgresbackend.Dialect("")); err == nil {
		t.Fatal("expected error: unknown backend")
	}
}

func TestBuildUserProvider_MemoryAndUnknownBackend(t *testing.T) {
	t.Parallel()
	if p, err := BuildUserProvider(config.IdentityConfig{}, nil, postgresbackend.Dialect("")); err != nil || p == nil {
		t.Fatalf("memory: provider=%v err=%v", p, err)
	}
	if _, err := BuildUserProvider(config.IdentityConfig{Backend: "carrier-pigeon"}, nil, postgresbackend.Dialect("")); err == nil {
		t.Fatal("expected error: unknown backend")
	}
}

func TestBuildSessionManager_MemoryAndSessionBackendOverride(t *testing.T) {
	t.Parallel()
	if m, err := BuildSessionManager(config.IdentityConfig{}, 0, nil, nil, postgresbackend.Dialect("")); err != nil || m == nil {
		t.Fatalf("memory: manager=%v err=%v", m, err)
	}
	// session_backend overrides the identity backend even when the
	// identity backend itself is memory — proves the override, not the
	// fallback, is honored.
	_, err := BuildSessionManager(config.IdentityConfig{Backend: "memory", SessionBackend: "redis"}, 0, nil, nil, postgresbackend.Dialect(""))
	if err == nil {
		t.Fatal("expected error: session_backend=redis without a redis client")
	}
	if _, err := BuildSessionManager(config.IdentityConfig{SessionBackend: "carrier-pigeon"}, 0, nil, nil, postgresbackend.Dialect("")); err == nil {
		t.Fatal("expected error: unknown session backend")
	}
}

// TestBuildClientCertExtractor_ThreadsPeerTrust proves the compiled
// security.trusted_proxies checker reaches the header extractor — the seam
// that gates a peer-forged cert header (unset checker = legacy behavior,
// covered by the nil-arg tests above).
func TestBuildClientCertExtractor_ThreadsPeerTrust(t *testing.T) {
	t.Parallel()
	checker, err := peertrust.NewChecker([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}
	ex, _, err := BuildClientCertExtractor(config.MTLSConfig{
		Enabled: true,
		Backend: "header",
		Header:  config.MTLSHeaderConfig{Name: "X-SSL-Client-Cert"},
	}, checker)
	if err != nil {
		t.Fatalf("BuildClientCertExtractor: %v", err)
	}
	h, ok := ex.(*security.HeaderClientCertExtractor)
	if !ok {
		t.Fatalf("extractor type = %T", ex)
	}
	if h.PeerTrust != checker {
		t.Errorf("PeerTrust not threaded: got %v, want the compiled checker", h.PeerTrust)
	}
}
