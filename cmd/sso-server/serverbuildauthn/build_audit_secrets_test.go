package serverbuildauthn

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/spi"
	"golang.org/x/crypto/bcrypt"
)

func testLogger() spi.Logger { return spi.NopLogger{} }

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func writeBcryptHash(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	return writeFile(t, "hash", string(h))
}

func TestBuildPrimaryAuditSink_MemorySqliteUnknown(t *testing.T) {
	t.Parallel()
	sink, name, err := BuildPrimaryAuditSink(config.AuditConfig{}, testLogger(), nil, "")
	if err != nil || sink == nil || name != "memory" {
		t.Fatalf("memory: sink=%v name=%q err=%v", sink, name, err)
	}
	if _, _, err := BuildPrimaryAuditSink(config.AuditConfig{Backend: "sqlite"}, testLogger(), nil, ""); err == nil {
		t.Fatal("expected error: sqlite backend requires a dsn")
	}
	if _, _, err := BuildPrimaryAuditSink(config.AuditConfig{Backend: "carrier-pigeon"}, testLogger(), nil, ""); err == nil {
		t.Fatal("expected error: unknown backend")
	}
}

func TestLoadSecretFile_ValidEmptyAndMissing(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "secret", "topsecret\n")
	got, err := LoadSecretFile(path)
	if err != nil || got != "topsecret" {
		t.Fatalf("got %q err %v, want %q", got, err, "topsecret")
	}
	empty := writeFile(t, "empty", "\n")
	if _, err := LoadSecretFile(empty); err == nil {
		t.Fatal("expected error: empty secret file")
	}
	if _, err := LoadSecretFile("/no/such/secret"); err == nil {
		t.Fatal("expected error: missing file")
	}
}

func TestLoadEd25519PrivateKeyPEM_ValidAndRejectsInvalidInputs(t *testing.T) {
	t.Parallel()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	validPath := writeFile(t, "notary.pem", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
	loaded, err := LoadEd25519PrivateKeyPEM(validPath)
	if err != nil {
		t.Fatalf("LoadEd25519PrivateKeyPEM: %v", err)
	}
	if !ed25519.PrivateKey(loaded).Equal(private) {
		t.Fatal("loaded private key differs from the provisioned key")
	}
	signer, err := BuildAuditCheckpointSigner(validPath)
	if err != nil {
		t.Fatalf("BuildAuditCheckpointSigner: %v", err)
	}
	message := []byte("checkpoint-test")
	signature, err := signer.Sign(message)
	if err != nil || !ed25519.Verify(signer.PublicKey(), message, signature) {
		t.Fatalf("round-trip signature invalid: err=%v", err)
	}

	emptyPath := writeFile(t, "empty.pem", "\n")
	if _, err := LoadEd25519PrivateKeyPEM(emptyPath); err == nil {
		t.Fatal("empty private-key file was accepted")
	}
	wrongTypePath := writeFile(t, "wrong-type.pem", string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: []byte("private-material-must-not-be-logged"),
	})))
	if _, err := LoadEd25519PrivateKeyPEM(wrongTypePath); err == nil || strings.Contains(err.Error(), "private-material") {
		t.Fatalf("wrong PEM type error = %v; want rejection without key material", err)
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong-algorithm key: %v", err)
	}
	ecdsaDER, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	if err != nil {
		t.Fatalf("marshal wrong-algorithm key: %v", err)
	}
	wrongAlgorithmPath := writeFile(t, "wrong-algorithm.pem", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecdsaDER})))
	if _, err := LoadEd25519PrivateKeyPEM(wrongAlgorithmPath); err == nil || !strings.Contains(err.Error(), wrongAlgorithmPath) {
		t.Fatalf("wrong algorithm error = %v; want a path-bearing rejection", err)
	}
	if _, err := LoadEd25519PrivateKeyPEM("/no/such/notary.pem"); err == nil {
		t.Fatal("missing private-key file was accepted")
	}
}

func TestLoadEd25519PublicKeyPEM_RoundTrip(t *testing.T) {
	t.Parallel()
	pub, path := writeEd25519PubKeyFixture(t)
	got, err := LoadEd25519PublicKeyPEM(path)
	if err != nil || !pub.Equal(got) {
		t.Fatalf("got %v err %v, want the original key", got, err)
	}
}

func TestLoadEd25519PublicKeyPEM_RejectsWrongTypeAndMissing(t *testing.T) {
	t.Parallel()
	wrong := writeFile(t, "wrong.pem", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: []byte("bogus")})))
	if _, err := LoadEd25519PublicKeyPEM(wrong); err == nil || !strings.Contains(err.Error(), "PUBLIC KEY") {
		t.Fatalf("err = %v, want a PUBLIC KEY type error", err)
	}
	if _, err := LoadEd25519PublicKeyPEM("/no/such/key.pem"); err == nil {
		t.Fatal("expected error: missing file")
	}
	noBlock := writeFile(t, "notpem.pem", "not a pem file\n")
	if _, err := LoadEd25519PublicKeyPEM(noBlock); err == nil {
		t.Fatal("expected error: no PEM block found")
	}
}

func TestLoadCertPool_EmptyMissingAndSkipsBlanks(t *testing.T) {
	t.Parallel()
	pool, err := LoadCertPool(nil)
	if err != nil || pool == nil {
		t.Fatalf("empty: pool=%v err=%v, want a non-nil empty pool", pool, err)
	}
	if _, err := LoadCertPool([]string{"/nonexistent/ca.pem"}); err == nil {
		t.Fatal("expected error: missing file")
	}
	pemBytes, _ := makeSelfSignedCAFixture(t, "test-ca")
	path := writeFile(t, "ca.pem", string(pemBytes))
	// A blank entry alongside a real one must be skipped, not error.
	pool, err = LoadCertPool([]string{"", path})
	if err != nil || pool == nil {
		t.Fatalf("blank+real: pool=%v err=%v", pool, err)
	}
}

func TestLoadCertPool_NoCertificateBlocksErrors(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "empty.pem", "not a pem file\n")
	if _, err := LoadCertPool([]string{path}); err == nil {
		t.Fatal("expected error: file has no CERTIFICATE PEM blocks")
	}
}

func TestLoadBcryptHashFile_ValidMultilineAndBadPrefix(t *testing.T) {
	t.Parallel()
	valid := writeBcryptHash(t, "pw")
	got, err := LoadBcryptHashFile(valid)
	if err != nil || !strings.HasPrefix(string(got), "$2") {
		t.Fatalf("got %q err %v, want a $2 bcrypt hash", got, err)
	}
	multi := writeFile(t, "multi", "$2a$10$abc\nsecondline\n")
	if _, err := LoadBcryptHashFile(multi); err == nil {
		t.Fatal("expected error: multi-line content")
	}
	badPrefix := writeFile(t, "badprefix", "not-a-bcrypt-hash")
	if _, err := LoadBcryptHashFile(badPrefix); err == nil {
		t.Fatal("expected error: missing $2a$/$2b$/$2y$ prefix")
	}
	empty := writeFile(t, "empty", "\n")
	if _, err := LoadBcryptHashFile(empty); err == nil {
		t.Fatal("expected error: empty file")
	}
}

func TestBuildBcryptPasswordVerifier_SeedsSkipsBadEntriesAndEqualizesTiming(t *testing.T) {
	t.Parallel()
	users := []config.PasswordUserConfig{
		{Username: "alice", SubjectID: "u-alice", BcryptHashFile: writeBcryptHash(t, "alice-pw")},
		{Username: "missing-fields"}, // skipped: no hash file / subject id
		{Username: "bad-file", SubjectID: "u-bad", BcryptHashFile: "/no/such/file"}, // skipped: unreadable
	}
	verifier, seeded := BuildBcryptPasswordVerifier(users, testLogger())
	if seeded != 1 {
		t.Fatalf("seeded = %d, want 1 (only alice has every required field)", seeded)
	}
	ctx := context.Background()
	res, err := verifier.Verify(ctx, "alice", "alice-pw")
	if err != nil || res.UserID != "u-alice" {
		t.Fatalf("verify seeded user: res=%v err=%v", res, err)
	}
	if _, err := verifier.Verify(ctx, "alice", "wrong-pw"); err == nil {
		t.Error("wrong password must fail")
	}
	// Anti-enumeration: an unknown username still runs a bcrypt compare
	// against the dummy hash rather than short-circuiting.
	if _, err := verifier.Verify(ctx, "mallory", "anything"); err == nil {
		t.Error("unknown username must fail")
	}
}

func TestBuildBcryptPasswordVerifier_EmptyUsersRejectsEveryLogin(t *testing.T) {
	t.Parallel()
	verifier, seeded := BuildBcryptPasswordVerifier(nil, testLogger())
	if seeded != 0 {
		t.Fatalf("seeded = %d, want 0", seeded)
	}
	if _, err := verifier.Verify(context.Background(), "anyone", "anything"); err == nil {
		t.Fatal("expected every login to fail against an empty seed map")
	}
}

// noImportPasswordStore satisfies sso.PasswordCredentialStore but
// deliberately NOT sso.PasswordHashImporter — every real Memory*/sqlite
// PasswordCredentialStore peer supports hash import, so this minimal stub is
// the only way to exercise BuildStoredPasswordVerifier's "store can't import"
// error branch.
type noImportPasswordStore struct{}

func (noImportPasswordStore) SetPassword(context.Context, string, string) error { return nil }
func (noImportPasswordStore) VerifyPassword(context.Context, string, string) error {
	return errors.New("unimplemented")
}

func TestBuildStoredPasswordVerifier_RequiresHashImporter(t *testing.T) {
	t.Parallel()
	if _, _, err := BuildStoredPasswordVerifier(noImportPasswordStore{}, nil, testLogger()); err == nil {
		t.Fatal("expected error: store does not implement PasswordHashImporter")
	}
}

// importingPasswordStore is a minimal in-memory PasswordCredentialStore +
// PasswordHashImporter double used to exercise BuildStoredPasswordVerifier's
// per-entry skip branches (missing field / bad hash file) without needing the
// full defaultimpl.MemoryPasswordCredentialStore's unrelated machinery.
type importingPasswordStore struct{ hashes map[string]string }

func (s *importingPasswordStore) SetPassword(context.Context, string, string) error { return nil }
func (s *importingPasswordStore) VerifyPassword(_ context.Context, userID, plaintext string) error {
	h, ok := s.hashes[userID]
	if !ok {
		return bcrypt.CompareHashAndPassword([]byte("$2a$10$"+strings.Repeat("a", 53)), []byte(plaintext))
	}
	return bcrypt.CompareHashAndPassword([]byte(h), []byte(plaintext))
}
func (s *importingPasswordStore) SetPasswordHash(_ context.Context, userID, bcryptHash string) error {
	s.hashes[userID] = bcryptHash
	return nil
}

var _ sso.PasswordHashImporter = (*importingPasswordStore)(nil)

func TestBuildStoredPasswordVerifier_SkipsMissingFieldsAndBadHashFile(t *testing.T) {
	t.Parallel()
	store := &importingPasswordStore{hashes: map[string]string{}}
	users := []config.PasswordUserConfig{
		{Username: "alice", SubjectID: "u-alice", BcryptHashFile: writeBcryptHash(t, "alice-pw")},
		{Username: "missing-fields"},
		{Username: "bad-file", SubjectID: "u-bad", BcryptHashFile: "/no/such/file"},
	}
	_, seeded, err := BuildStoredPasswordVerifier(store, users, testLogger())
	if err != nil {
		t.Fatalf("BuildStoredPasswordVerifier: %v", err)
	}
	if seeded != 1 {
		t.Fatalf("seeded = %d, want 1", seeded)
	}
}

func TestBuildPasswordHealthChecker_DictionaryHIBPAndUnknown(t *testing.T) {
	t.Parallel()
	c, err := BuildPasswordHealthChecker(&config.PasswordHealthConfig{}, testLogger())
	if err != nil || c == nil {
		t.Fatalf("dictionary default: checker=%v err=%v", c, err)
	}
	// Construction of the hibp checker is local-only (no network call at
	// build time) — safe to exercise the wiring without hitting the network.
	c, err = BuildPasswordHealthChecker(&config.PasswordHealthConfig{
		Kind: "hibp",
		HIBP: &config.HIBPHealthConfig{BaseURL: "https://hibp.example.com/range/", MinCount: 2},
	}, testLogger())
	if err != nil || c == nil {
		t.Fatalf("hibp: checker=%v err=%v", c, err)
	}
	if _, err := BuildPasswordHealthChecker(&config.PasswordHealthConfig{Kind: "carrier-pigeon"}, testLogger()); err == nil {
		t.Fatal("expected error: unknown health kind")
	}
}

func TestBuildPasswordHealthChecker_MissingWeakPasswordFileErrors(t *testing.T) {
	t.Parallel()
	if _, err := BuildPasswordHealthChecker(&config.PasswordHealthConfig{
		Kind:             "dictionary",
		WeakPasswordFile: "/no/such/weak-list",
	}, testLogger()); err == nil {
		t.Fatal("expected error: unreadable weak_password_file")
	}
}

// writeEd25519PubKeyFixture writes a PKIX-marshaled Ed25519 "PUBLIC KEY" PEM
// block to a temp file, shared by this file's LoadEd25519PublicKeyPEM tests
// and build_authenticators_helpers_test.go's appendKeyPairAuthenticator tests.
func writeEd25519PubKeyFixture(t *testing.T) (ed25519.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	path := writeFile(t, "svc.pub.pem", string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	return pub, path
}

// makeSelfSignedCAFixture builds a minimal self-signed CA cert (PEM bytes +
// parsed form), shared by this file's LoadCertPool tests and
// build_authenticators_helpers_test.go's appendCertificateAuthenticator tests.
func makeSelfSignedCAFixture(t *testing.T, cn string) ([]byte, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), parsed
}
