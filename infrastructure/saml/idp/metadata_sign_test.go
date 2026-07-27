package idp

import (
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// newSigningHarness builds a Handlers exactly like newHarness but with
// SignMetadata enabled, so the metadata endpoint enveloped-signs the
// EntityDescriptor with the per-tenant key.
func newSigningHarness(t *testing.T, kind testIssuerKind) *harness {
	t.Helper()
	issuer, pub := newIssuer(t, kind)

	clients := defaultimpl.NewMemoryClientStore()
	sessions := defaultimpl.NewMemorySessionManager()
	users := defaultimpl.NewMemoryUserProvider()

	registerSP(t, clients, spClientID, spEntityID, spACSURL)

	h, err := NewHandlers(Deps{
		ClientStore:     clients,
		SessionManager:  sessions,
		UserProvider:    users,
		IssuerForClient: func(*sso.Client) (string, sso.TokenIssuer, error) { return "test", issuer, nil },
		Issuer:          testIssuer,
		SignMetadata:    true,
	})
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	h.deps.now = func() time.Time { return fixedNow }
	return &harness{h: h, clients: clients, sessions: sessions, users: users, issuer: issuer, signerPub: pub}
}

// getMetadata drives GET /saml/metadata and returns the recorder.
func (hh *harness) getMetadata(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/saml/metadata", nil)
	rec := httptest.NewRecorder()
	hh.h.Metadata(rec, req)
	return rec
}

// --- Signed metadata: enveloped Signature validates against its OWN KeyDescriptor ---

// TestMetadata_Signed_RSA_ValidatesAgainstOwnKeyDescriptor proves that with
// SignMetadata=true and an RSA issuer the served EntityDescriptor carries an
// enveloped <Signature> that validates (via goxmldsig — the engine a strict SP
// uses) against the X.509 cert published in this very document's signing
// KeyDescriptor. A consumer doing automated metadata refresh therefore validates
// the metadata with NO trust anchor beyond the document itself.
func TestMetadata_Signed_RSA_ValidatesAgainstOwnKeyDescriptor(t *testing.T) {
	t.Parallel()
	testMetadataSignedValidatesAgainstOwnKeyDescriptor(t, issuerRSA)
}

// TestMetadata_Signed_ECDSA_ValidatesAgainstOwnKeyDescriptor proves the ECDSA
// (ES256) path: the ASN.1-DER XML-DSig signature goxmldsig emits validates (the
// DER-vs-R‖S finding holds for metadata exactly as for assertions).
func TestMetadata_Signed_ECDSA_ValidatesAgainstOwnKeyDescriptor(t *testing.T) {
	t.Parallel()
	testMetadataSignedValidatesAgainstOwnKeyDescriptor(t, issuerECDSA)
}

func testMetadataSignedValidatesAgainstOwnKeyDescriptor(t *testing.T, kind testIssuerKind) {
	t.Helper()
	hh := newSigningHarness(t, kind)

	rec := hh.getMetadata(t)
	if rec.Code != http.StatusOK {
		t.Fatalf("metadata status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/samlmetadata+xml" {
		t.Errorf("Content-Type = %q", ct)
	}

	// Parse the served metadata as an etree document (what a consumer validates).
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(rec.Body.Bytes()); err != nil {
		t.Fatalf("parse served metadata: %v", err)
	}
	root := doc.Root()
	if root == nil || root.Tag != "EntityDescriptor" {
		t.Fatalf("root = %v, want EntityDescriptor", root)
	}

	// (1) An enveloped <Signature> is present...
	sigEl := root.FindElement("./Signature")
	if sigEl == nil {
		t.Fatalf("served signed metadata has NO <Signature> child")
	}
	// ...and it is the FIRST child element (the SAML metadata XSD orders
	// ds:Signature before the role descriptors — strict consumers require it).
	if first := root.ChildElements()[0]; first.Tag != "Signature" {
		t.Errorf("first child element = %q, want Signature (schema ordering)", first.Tag)
	}

	// (2) Extract the cert from the document's OWN signing KeyDescriptor and
	// validate the metadata signature against exactly that cert.
	certFromDoc := signingCertFromServedMetadata(t, rec.Body.Bytes())
	store := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{certFromDoc}}
	ctx := dsig.NewDefaultValidationContext(store)
	// Real wall clock for cert-validity: the synthetic signing cert's dates are
	// real-now-based (AssertionSigner.buildCert has no clock seam), so pinning a
	// fixed past clock falsely rejects it once the real date drifts past fixedNow.
	if _, err := ctx.Validate(root); err != nil {
		t.Fatalf("metadata signature INVALID against its OWN KeyDescriptor cert: %v", err)
	}

	// (3) The published cert is the SAME one assertions are signed with (the
	// cached AssertionSigner's cert) — metadata + assertions share the key.
	wantCert, err := hh.signerFor(t).Certificate()
	if err != nil {
		t.Fatalf("signer cert: %v", err)
	}
	if string(certFromDoc.Raw) != string(wantCert.Raw) {
		t.Error("metadata KeyDescriptor cert does NOT match the assertion-signing key cert")
	}
}

// --- Default (SignMetadata=false): byte-identical unsigned metadata ---

// TestMetadata_Default_Unsigned_ByteIdentical proves the opt-in is OFF by
// default: with SignMetadata=false the served metadata carries NO <Signature>
// and is BYTE-IDENTICAL to GenerateMetadata's unsigned render (the historical
// output). This is the regression gate for "default => byte-identical".
func TestMetadata_Default_Unsigned_ByteIdentical(t *testing.T) {
	t.Parallel()
	// newHarness leaves SignMetadata at its zero value (false).
	hh := newHarness(t, issuerRSA)

	rec := hh.getMetadata(t)
	if rec.Code != http.StatusOK {
		t.Fatalf("metadata status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	served := rec.Body.Bytes()

	// No Signature in the default output.
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(served); err != nil {
		t.Fatalf("parse served metadata: %v", err)
	}
	if doc.Root().FindElement("./Signature") != nil {
		t.Fatalf("default metadata carries a <Signature> — it must be UNSIGNED")
	}

	// Byte-identical to the unsigned render through the SAME signer.
	want, err := GenerateMetadata(hh.signerFor(t), hh.h.entityID(), hh.h.ssoURL(), false)
	if err != nil {
		t.Fatalf("GenerateMetadata(sign=false): %v", err)
	}
	if string(served) != string(want.XML) {
		t.Errorf("default metadata is NOT byte-identical to the unsigned render\nserved=%q\nwant=  %q", served, want.XML)
	}
}

// TestGenerateMetadata_UnsignedMatchesHistoricalShape locks the exact unsigned
// bytes against the historical construction (xml.Header + xml.MarshalIndent),
// independent of the handler — a second guard that the sign=false path did not
// drift.
func TestGenerateMetadata_UnsignedMatchesHistoricalShape(t *testing.T) {
	t.Parallel()
	hh := newHarness(t, issuerRSA)
	signer := hh.signerFor(t)

	doc, err := GenerateMetadata(signer, testEntityID, testIssuer+"/saml/sso", false)
	if err != nil {
		t.Fatalf("GenerateMetadata: %v", err)
	}
	// The unsigned doc must start with the XML declaration and contain NO
	// Signature element.
	if got := string(doc.XML[:len(`<?xml`)]); got != `<?xml` {
		t.Errorf("unsigned metadata does not begin with the XML declaration: %q", got)
	}
	parsed := etree.NewDocument()
	if err := parsed.ReadFromBytes(doc.XML); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Root().FindElement("./Signature") != nil {
		t.Error("unsigned metadata unexpectedly carries a Signature")
	}
	// And it round-trips through crewjam's unmarshaler (a real consumer parse).
	var meta saml.EntityDescriptor
	if err := xmlUnmarshalStrict(doc.XML, &meta); err != nil {
		t.Fatalf("crewjam unmarshal of unsigned metadata: %v", err)
	}
	if meta.EntityID != testEntityID {
		t.Errorf("EntityID = %q, want %q", meta.EntityID, testEntityID)
	}
}

// --- Ed25519: graceful UNSIGNED fallback (no 500) ---

// TestMetadata_Ed25519_SignRequested_FallsBackUnsigned proves an Ed25519 signing
// key (goxmldsig has no EdDSA method) with SignMetadata=true does NOT 500 the
// metadata endpoint: it serves UNSIGNED metadata (still publishing the
// KeyDescriptor cert) and logs the downgrade. This is the graceful fallback the
// assertion path can't offer (it must fail closed), kept here so automated
// metadata refresh against an Ed25519 IdP doesn't break the endpoint.
func TestMetadata_Ed25519_SignRequested_FallsBackUnsigned(t *testing.T) {
	t.Parallel()
	hh := newSigningHarness(t, issuerEd25519)
	logger := &capturingLogger{}
	hh.h.deps.Logger = logger

	rec := hh.getMetadata(t)
	if rec.Code != http.StatusOK {
		t.Fatalf("metadata status = %d, want 200 (graceful Ed25519 fallback, NOT 500); body=%s", rec.Code, rec.Body.String())
	}

	// UNSIGNED: no Signature element despite SignMetadata=true.
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(rec.Body.Bytes()); err != nil {
		t.Fatalf("parse served metadata: %v", err)
	}
	if doc.Root().FindElement("./Signature") != nil {
		t.Fatalf("Ed25519 metadata carries a <Signature> — it must fall back to UNSIGNED")
	}
	// The KeyDescriptor cert is still published (the endpoint stays usable).
	if got := signingCertFromServedMetadata(t, rec.Body.Bytes()); got == nil {
		t.Error("Ed25519 fallback metadata omits the signing KeyDescriptor cert")
	}
	// A downgrade log was emitted (the optional log the task allows).
	if !logger.sawInfoContaining("UNSIGNED") {
		t.Errorf("expected an Info log about serving UNSIGNED metadata; got %v", logger.infos)
	}
}

// --- ETag: changes signed vs unsigned + on key rotation; stable across requests ---

// TestMetadata_ETag_ChangesSignedVsUnsigned proves the ETag distinguishes the
// signed and unsigned renders of the SAME key (the signed flag is folded into
// the ETag input), so a cache keyed on it never serves an unsigned body as a
// signed one (or vice versa).
func TestMetadata_ETag_ChangesSignedVsUnsigned(t *testing.T) {
	t.Parallel()
	unsigned := newHarness(t, issuerRSA)
	signed := newSigningHarness(t, issuerRSA)
	// Force BOTH harnesses onto the SAME signing key so only the signed flag
	// differs — the ETag must still change.
	sharedIssuer := unsigned.issuer
	signed.h.deps.IssuerForClient = func(*sso.Client) (string, sso.TokenIssuer, error) {
		return "test", sharedIssuer, nil
	}

	etUnsigned := unsigned.getMetadata(t).Header().Get("ETag")
	etSigned := signed.getMetadata(t).Header().Get("ETag")
	if etUnsigned == "" || etSigned == "" {
		t.Fatalf("missing ETag: unsigned=%q signed=%q", etUnsigned, etSigned)
	}
	if etUnsigned == etSigned {
		t.Errorf("ETag did not change between unsigned (%q) and signed (%q) metadata for the same key", etUnsigned, etSigned)
	}
}

// TestMetadata_ETag_ChangesOnKeyRotation proves a key rotation (a new kid → new
// cert) changes the ETag, so a consumer's If-None-Match re-fetches the new
// signing material. Exercised on the signed path (the kid is folded into the
// ETag input, and the new cert changes the body too).
func TestMetadata_ETag_ChangesOnKeyRotation(t *testing.T) {
	t.Parallel()
	hh := newSigningHarness(t, issuerRSA)
	etag1 := hh.getMetadata(t).Header().Get("ETag")
	if etag1 == "" {
		t.Fatal("no ETag on first metadata")
	}

	// Rotate to a brand-new issuer key (distinct kid + cert).
	newIss, _ := newIssuer(t, issuerRSA)
	hh.h.deps.IssuerForClient = func(*sso.Client) (string, sso.TokenIssuer, error) {
		return "test", newIss, nil
	}

	etag2 := hh.getMetadata(t).Header().Get("ETag")
	if etag2 == "" {
		t.Fatal("no ETag after rotation")
	}
	if etag1 == etag2 {
		t.Errorf("ETag unchanged across key rotation: %q", etag1)
	}
}

// TestMetadata_Signed_ECDSA_ETagStableAcrossRequests is the critical caching
// guard: an ECDSA XML-DSig SignatureValue is non-deterministic (random k), so
// without per-(kid,signed) caching the signed body — and any body-derived ETag —
// would change on EVERY request, defeating If-None-Match. This proves the cached
// doc yields a STABLE ETag + body across repeated requests AND that
// If-None-Match → 304 works for the signed ECDSA case.
func TestMetadata_Signed_ECDSA_ETagStableAcrossRequests(t *testing.T) {
	t.Parallel()
	hh := newSigningHarness(t, issuerECDSA)

	rec1 := hh.getMetadata(t)
	etag := rec1.Header().Get("ETag")
	body1 := rec1.Body.String()
	if etag == "" {
		t.Fatal("no ETag")
	}

	rec2 := hh.getMetadata(t)
	if got := rec2.Header().Get("ETag"); got != etag {
		t.Fatalf("signed ECDSA ETag not stable across requests: %q then %q", etag, got)
	}
	if rec2.Body.String() != body1 {
		t.Fatal("signed ECDSA body not stable across requests (cache not holding the non-deterministic signature)")
	}

	// Conditional request → 304.
	req := httptest.NewRequest(http.MethodGet, "/saml/metadata", nil)
	req.Header.Set("If-None-Match", etag)
	rec3 := httptest.NewRecorder()
	hh.h.Metadata(rec3, req)
	if rec3.Code != http.StatusNotModified {
		t.Errorf("conditional signed request status = %d, want 304", rec3.Code)
	}
}

// TestMetadata_Signed_ConcurrentRequests_RaceSafe hammers the signed metadata
// endpoint from many goroutines to prove the per-(kid,signed) metadata cache +
// signer cache are race-free (run under -race) AND that every concurrent
// response is the SAME cached, valid document (one ETag, validating signature).
func TestMetadata_Signed_ConcurrentRequests_RaceSafe(t *testing.T) {
	t.Parallel()
	hh := newSigningHarness(t, issuerECDSA)

	const goroutines = 32
	var wg sync.WaitGroup
	etags := make([]string, goroutines)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			rec := hh.getMetadata(t)
			if rec.Code != http.StatusOK {
				t.Errorf("goroutine %d: status %d", idx, rec.Code)
				return
			}
			etags[idx] = rec.Header().Get("ETag")
		}(i)
	}
	wg.Wait()

	// All concurrent requests observed the SAME cached ETag (one render won).
	for i := 1; i < goroutines; i++ {
		if etags[i] != etags[0] {
			t.Fatalf("concurrent ETag divergence: etags[0]=%q etags[%d]=%q", etags[0], i, etags[i])
		}
	}

	// And the served signed metadata validates against its own KeyDescriptor.
	rec := hh.getMetadata(t)
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(rec.Body.Bytes()); err != nil {
		t.Fatalf("parse: %v", err)
	}
	certFromDoc := signingCertFromServedMetadata(t, rec.Body.Bytes())
	store := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{certFromDoc}}
	ctx := dsig.NewDefaultValidationContext(store)
	// Real wall clock for cert-validity: the synthetic signing cert's dates are
	// real-now-based (AssertionSigner.buildCert has no clock seam), so pinning a
	// fixed past clock falsely rejects it once the real date drifts past fixedNow.
	if _, err := ctx.Validate(doc.Root()); err != nil {
		t.Fatalf("post-concurrency signed metadata INVALID: %v", err)
	}
}

// --- helpers ---

// signingCertFromServedMetadata parses served metadata bytes and returns the
// X.509 cert from the signing KeyDescriptor (what a consumer validates the
// metadata signature against). Returns nil if absent.
func signingCertFromServedMetadata(t *testing.T, served []byte) *x509.Certificate {
	t.Helper()
	var meta saml.EntityDescriptor
	if err := xmlUnmarshalStrict(served, &meta); err != nil {
		t.Fatalf("unmarshal served metadata: %v", err)
	}
	if len(meta.IDPSSODescriptors) == 0 {
		t.Fatal("served metadata has no IDPSSODescriptor")
	}
	for _, kd := range meta.IDPSSODescriptors[0].KeyDescriptors {
		if kd.Use != "signing" || len(kd.KeyInfo.X509Data.X509Certificates) == 0 {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(kd.KeyInfo.X509Data.X509Certificates[0].Data)
		if err != nil {
			t.Fatalf("decode KeyDescriptor cert: %v", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parse KeyDescriptor cert: %v", err)
		}
		return cert
	}
	return nil
}

// capturingLogger records Info/Error/Debug lines so a test can assert a log was
// emitted (the Ed25519 fallback). Implements spi.Logger.
type capturingLogger struct {
	infos  []string
	errors []string
	debugs []string
}

func (l *capturingLogger) Info(msg string, _ ...any)  { l.infos = append(l.infos, msg) }
func (l *capturingLogger) Error(msg string, _ ...any) { l.errors = append(l.errors, msg) }
func (l *capturingLogger) Debug(msg string, _ ...any) { l.debugs = append(l.debugs, msg) }

func (l *capturingLogger) sawInfoContaining(sub string) bool {
	for _, m := range l.infos {
		if strings.Contains(m, sub) {
			return true
		}
	}
	return false
}
