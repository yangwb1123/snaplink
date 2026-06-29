package webauthn

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
)

// exampleBlobPath is go-webauthn's own example MDS blob (extracted verbatim
// from the library's metadata_test fixtures) — a real JWS signed by
// metadata.ExampleMDSRoot carrying one authenticator entry. Using the
// library's own fixture means the test exercises the SAME JWS-chain
// verification path production uses, not a hand-rolled stand-in.
//
// NOTE on test depth: this suite covers provider construction, the gw.Config
// wiring, and every decode-failure / fail-loud path. It deliberately does NOT
// synthesize a full attestation-with-cert-chain ceremony and run it against
// the provider — that requires forging a CTAP attestation object whose x5c
// chains to ExampleMDSRoot, which is impractical to construct here. The
// attestation-chain validation itself (ValidateMetadata rejecting an unrooted
// chain / unknown AAGUID) is covered by go-webauthn's own protocol +
// metadata tests; this suite verifies we feed go-webauthn a correctly
// root-validated provider and wire it onto gw.Config.MDS.
const exampleBlobPath = "testdata/example_mds_blob.jws"

func readExampleBlob(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(exampleBlobPath)
	if err != nil {
		t.Fatalf("read example MDS blob: %v", err)
	}
	return raw
}

func TestMDSSource_Configured(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		src  MDSSource
		want bool
	}{
		{"zero", MDSSource{}, false},
		{"only custom root", MDSSource{CustomRootPEM: metadata.ExampleMDSRoot}, false},
		{"file", MDSSource{FilePath: "x"}, true},
		{"fetch", MDSSource{FetchURL: "https://x"}, true},
		{"whitespace file", MDSSource{FilePath: "   "}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.src.Configured(); got != tc.want {
				t.Fatalf("Configured() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMDSSource_Validate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		src     MDSSource
		wantErr string
	}{
		{"neither", MDSSource{}, "neither file_path nor fetch_url"},
		{"both", MDSSource{FilePath: "a", FetchURL: "https://b"}, "BOTH file_path and fetch_url"},
		{"plaintext url", MDSSource{FetchURL: "http://insecure"}, "must be https"},
		{"ok file", MDSSource{FilePath: "a"}, ""},
		{"ok https", MDSSource{FetchURL: "https://b"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.src.validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validate() = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestBuildMDSProvider_FromFile decodes the real example blob (custom test
// root) and confirms the provider is built with the adversary-resistant
// validation posture (require-entry + validate-trust-anchor ON, permit-zero
// OFF) — the settings under which go-webauthn rejects an unknown AAGUID or an
// unrooted attestation chain.
func TestBuildMDSProvider_FromFile(t *testing.T) {
	t.Parallel()
	provider, err := BuildMDSProvider(MDSSource{
		FilePath:      exampleBlobPath,
		CustomRootPEM: metadata.ExampleMDSRoot,
	})
	if err != nil {
		t.Fatalf("BuildMDSProvider: %v", err)
	}
	if provider == nil {
		t.Fatal("BuildMDSProvider returned nil provider")
	}
	ctx := t.Context()
	if !provider.GetValidateEntry(ctx) {
		t.Error("provider should require a metadata entry (adversary-resistance: unknown AAGUID rejected)")
	}
	if !provider.GetValidateTrustAnchor(ctx) {
		t.Error("provider should validate the trust anchor (adversary-resistance: unrooted chain rejected)")
	}
	if provider.GetValidateEntryPermitZeroAAGUID(ctx) {
		t.Error("provider should NOT permit the zero AAGUID")
	}
}

// TestBuildMDSProvider_WrongRootFailsLoud is the fail-loud gate: a blob whose
// JWS chain does not verify against the configured root (here the default FIDO
// production root, which did NOT sign the example/test blob) is rejected at
// build time. This is the security-critical property — we must never silently
// run without MDS when the operator asked for it.
func TestBuildMDSProvider_WrongRootFailsLoud(t *testing.T) {
	t.Parallel()
	// No CustomRootPEM ⇒ defaults to the built-in FIDO production root, which
	// is the WRONG root for the example (test-root-signed) blob.
	_, err := BuildMDSProvider(MDSSource{FilePath: exampleBlobPath})
	if err == nil {
		t.Fatal("expected wrong-root blob to fail loud, got nil error")
	}
	if !strings.Contains(err.Error(), "decode MDS blob") {
		t.Fatalf("error should name the decode/chain failure, got: %v", err)
	}
}

// TestBuildMDSProvider_TamperedBlobFailsLoud flips a byte in the blob; the JWS
// signature check must reject it (even with the correct root).
func TestBuildMDSProvider_TamperedBlobFailsLoud(t *testing.T) {
	t.Parallel()
	raw := readExampleBlob(t)
	tampered := make([]byte, len(raw))
	copy(tampered, raw)
	// Corrupt a byte in the JWS payload section (after the first '.').
	dot := strings.IndexByte(string(tampered), '.')
	if dot < 0 || dot+10 >= len(tampered) {
		t.Fatal("unexpected blob shape")
	}
	if tampered[dot+10] == 'A' {
		tampered[dot+10] = 'B'
	} else {
		tampered[dot+10] = 'A'
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "tampered.jws")
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("write tampered blob: %v", err)
	}
	_, err := BuildMDSProvider(MDSSource{FilePath: path, CustomRootPEM: metadata.ExampleMDSRoot})
	if err == nil {
		t.Fatal("expected tampered blob to fail loud, got nil error")
	}
}

func TestBuildMDSProvider_MissingFileFailsLoud(t *testing.T) {
	t.Parallel()
	_, err := BuildMDSProvider(MDSSource{FilePath: "testdata/does_not_exist.jws"})
	if err == nil {
		t.Fatal("expected missing-file error")
	}
	if !strings.Contains(err.Error(), "read MDS blob file") {
		t.Fatalf("error should name the file read, got: %v", err)
	}
}

func TestBuildMDSProvider_EmptyFileFailsLoud(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.jws")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write empty file: %v", err)
	}
	_, err := BuildMDSProvider(MDSSource{FilePath: path})
	if err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("expected empty-file error, got: %v", err)
	}
}

func TestBuildMDSProvider_BothSourcesFailLoud(t *testing.T) {
	t.Parallel()
	_, err := BuildMDSProvider(MDSSource{FilePath: "a", FetchURL: "https://b"})
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("expected both-sources error, got: %v", err)
	}
}

func TestBuildMDSProvider_NeitherSourceFailsLoud(t *testing.T) {
	t.Parallel()
	_, err := BuildMDSProvider(MDSSource{})
	if err == nil || !strings.Contains(err.Error(), "neither file_path nor fetch_url") {
		t.Fatalf("expected unconfigured-source error, got: %v", err)
	}
}

// TestBuildMDSProvider_FetchReachesTransport serves the blob over an
// httptest TLS server (untrusted self-signed cert) and confirms the fetch
// path reaches the net/http layer and surfaces the transport error loud. The
// successful-decode logic is identical to the file path (same DecodeBytes),
// which the file tests cover; here we prove the fetch wiring + fail-loud.
func TestBuildMDSProvider_FetchReachesTransport(t *testing.T) {
	t.Parallel()
	raw := readExampleBlob(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(raw)
	}))
	defer srv.Close()
	_, err := BuildMDSProvider(MDSSource{
		FetchURL:      srv.URL, // https, but untrusted self-signed cert
		CustomRootPEM: metadata.ExampleMDSRoot,
		FetchTimeout:  2 * time.Second,
	})
	if err == nil {
		t.Fatal("expected untrusted-TLS fetch to fail loud")
	}
	if !strings.Contains(err.Error(), "fetch MDS blob") {
		t.Fatalf("error should name the fetch, got: %v", err)
	}
}

// TestBuildMDSProvider_FetchRejectsPlaintext confirms the https guard.
func TestBuildMDSProvider_FetchRejectsPlaintext(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	_, err := BuildMDSProvider(MDSSource{FetchURL: srv.URL}) // http://...
	if err == nil || !strings.Contains(err.Error(), "must be https") {
		t.Fatalf("expected https-guard error, got: %v", err)
	}
}

// TestNewHelper_MDSNilByDefault proves the default-off byte-identical
// contract: a Config WITHOUT MDS leaves gw.Config.MDS nil, so go-webauthn's
// VerifyAttestation performs no metadata validation (its mds==nil early
// return) — identical to the pre-MDS ceremony.
func TestNewHelper_MDSNilByDefault(t *testing.T) {
	t.Parallel()
	h, err := NewHelper(Config{
		RPID:      "example.com",
		RPOrigins: []string{"https://sso.example.com"},
	}, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewHelper: %v", err)
	}
	if h.core.Config.MDS != nil {
		t.Fatal("default Config must leave gw.Config.MDS nil (byte-identical default-off)")
	}
}

// TestNewHelper_MDSWired proves a provided MDS provider reaches gw.Config.MDS,
// so go-webauthn's VerifyAttestation will run metadata validation against it.
func TestNewHelper_MDSWired(t *testing.T) {
	t.Parallel()
	provider, err := BuildMDSProvider(MDSSource{
		FilePath:      exampleBlobPath,
		CustomRootPEM: metadata.ExampleMDSRoot,
	})
	if err != nil {
		t.Fatalf("BuildMDSProvider: %v", err)
	}
	h, err := NewHelper(Config{
		RPID:      "example.com",
		RPOrigins: []string{"https://sso.example.com"},
		MDS:       provider,
	}, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewHelper: %v", err)
	}
	if h.core.Config.MDS == nil {
		t.Fatal("Config.MDS must reach gw.Config.MDS when wired")
	}
	// The wired provider must carry the adversary-resistant posture.
	if !h.core.Config.MDS.GetValidateTrustAnchor(t.Context()) {
		t.Fatal("wired provider should validate the trust anchor")
	}
}
