package sp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
)

// These helpers mint SIGNED SAML assertions under our control so the tests can
// exercise the validator adversarially (valid, bad-signer, wrong-audience,
// wrong-recipient, expired, replayed, multi-assertion). The signing path
// mirrors crewjam's IdpAuthnRequest.MakeAssertionEl exactly: build the
// assertion element, SignEnveloped it with goxmldsig against the IdP key, and
// attach the resulting Signature as the assertion's last child — so what we
// feed the SP is byte-shaped like a real IdP response.

const rsaSHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

// idpKeypair is a self-signed cert + key standing in for the IdP signing key.
type idpKeypair struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

// newIDPKeypair generates a fresh RSA keypair + self-signed cert valid in a
// wide window around now (so goxmldsig's cert-validity check during signature
// verification never trips on clock).
func newIDPKeypair(t *testing.T) *idpKeypair {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate IdP key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "test-idp"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create IdP cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse IdP cert: %v", err)
	}
	return &idpKeypair{key: key, cert: cert}
}

// certPEM returns the PEM CERTIFICATE encoding (for SPConfig.IDPCert).
func (k *idpKeypair) certPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: k.cert.Raw})
}

// assertionParams describes the assertion to mint. Zero values yield a VALID
// assertion (when fed through buildSignedResponse with the matching SP config);
// each field is a knob for an attack variant.
type assertionParams struct {
	id           string
	idpEntityID  string
	spEntityID   string // audience
	recipient    string // SubjectConfirmationData.Recipient (= SP ACS URL)
	nameID       string
	inResponseTo string // Response InResponseTo (SP-initiated correlation)
	notBefore    time.Time
	notOnOrAfter time.Time
	attrs        map[string]string
}

// defaultAssertionParams returns params that validate against an SP configured
// with spEntityID + recipient, signed by the IdP whose entity ID is idpEntityID.
// InResponseTo is set so the response satisfies the SP-initiated-only posture
// (the stateless default); IdP-initiated tests clear it.
func defaultAssertionParams(idpEntityID, spEntityID, recipient string) assertionParams {
	now := time.Now()
	return assertionParams{
		id:           "id-" + randHex(),
		idpEntityID:  idpEntityID,
		spEntityID:   spEntityID,
		recipient:    recipient,
		nameID:       "alice@example.com",
		inResponseTo: "id-req-" + randHex(),
		notBefore:    now.Add(-1 * time.Minute),
		notOnOrAfter: now.Add(5 * time.Minute),
		attrs: map[string]string{
			"email": "alice@example.com",
			"role":  "admin",
		},
	}
}

// buildAssertion constructs the crewjam Assertion struct from params (unsigned).
func buildAssertion(p assertionParams) *saml.Assertion {
	a := &saml.Assertion{
		ID:           p.id,
		IssueInstant: time.Now(),
		Version:      "2.0",
		Issuer: saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  p.idpEntityID,
		},
		Subject: &saml.Subject{
			NameID: &saml.NameID{
				Format: string(saml.EmailAddressNameIDFormat),
				Value:  p.nameID,
			},
			SubjectConfirmations: []saml.SubjectConfirmation{{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				SubjectConfirmationData: &saml.SubjectConfirmationData{
					NotOnOrAfter: p.notOnOrAfter,
					Recipient:    p.recipient,
				},
			}},
		},
		Conditions: &saml.Conditions{
			NotBefore:    p.notBefore,
			NotOnOrAfter: p.notOnOrAfter,
			AudienceRestrictions: []saml.AudienceRestriction{{
				Audience: saml.Audience{Value: p.spEntityID},
			}},
		},
		AuthnStatements: []saml.AuthnStatement{{
			AuthnInstant: time.Now(),
			AuthnContext: saml.AuthnContext{
				AuthnContextClassRef: &saml.AuthnContextClassRef{
					Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
				},
			},
		}},
	}
	if len(p.attrs) > 0 {
		stmt := saml.AttributeStatement{}
		for name, val := range p.attrs {
			stmt.Attributes = append(stmt.Attributes, saml.Attribute{
				Name:       name,
				NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
				Values:     []saml.AttributeValue{{Type: "xs:string", Value: val}},
			})
		}
		a.AttributeStatements = []saml.AttributeStatement{stmt}
	}
	return a
}

// signAssertionEl signs the assertion element with the given IdP key and
// attaches the Signature as the last child (mirrors crewjam MakeAssertionEl).
func signAssertionEl(t *testing.T, a *saml.Assertion, signer *idpKeypair) *etree.Element {
	t.Helper()
	ctx, err := dsig.NewSigningContext(signer.key, [][]byte{signer.cert.Raw})
	if err != nil {
		t.Fatalf("new signing context: %v", err)
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(rsaSHA256); err != nil {
		t.Fatalf("set signature method: %v", err)
	}
	assertionEl := a.Element()
	signedEl, err := ctx.SignEnveloped(assertionEl)
	if err != nil {
		t.Fatalf("sign enveloped: %v", err)
	}
	// crewjam pulls the appended Signature element back onto the struct so the
	// re-rendered Element() carries it; we just use the signed element directly.
	return signedEl
}

// responseFrom wraps one or more (already-built) assertion elements into a SAML
// Response element and returns the base64 SAMLResponse string. The Response
// itself is unsigned (assertions carry the signature), which is the common
// shape and the one ParseResponse handles when assertions are signed.
func responseFrom(idpEntityID, destination, inResponseTo string, assertionEls ...*etree.Element) string {
	resp := &saml.Response{
		ID:           "id-" + randHex(),
		Version:      "2.0",
		IssueInstant: time.Now(),
		Destination:  destination,
		InResponseTo: inResponseTo,
		Issuer: &saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  idpEntityID,
		},
		Status: saml.Status{
			StatusCode: saml.StatusCode{Value: saml.StatusSuccess},
		},
	}
	respEl := resp.Element()
	for _, ae := range assertionEls {
		respEl.AddChild(ae)
	}
	doc := etree.NewDocument()
	doc.SetRoot(respEl)
	raw, err := doc.WriteToBytes()
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// mintValidResponse is the happy-path convenience: builds + signs an assertion
// per params and wraps it into a base64 SAMLResponse destined for the SP ACS.
func mintValidResponse(t *testing.T, p assertionParams, signer *idpKeypair, destination string) string {
	t.Helper()
	el := signAssertionEl(t, buildAssertion(p), signer)
	return responseFrom(p.idpEntityID, destination, p.inResponseTo, el)
}

func randHex() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	const hex = "0123456789abcdef"
	out := make([]byte, 32)
	for i, x := range b {
		out[i*2] = hex[x>>4]
		out[i*2+1] = hex[x&0x0f]
	}
	return string(out)
}

// idpMetadataXML renders a minimal-but-valid SAML IdP EntityDescriptor XML
// carrying signer's cert as the signing KeyDescriptor + an HTTP-Redirect SSO
// endpoint, so samlsp.ParseMetadata accepts it and the SP pins the cert.
func idpMetadataXML(t *testing.T, signer *idpKeypair, entityID, ssoURL string) []byte {
	t.Helper()
	ed := &saml.EntityDescriptor{
		EntityID:          entityID,
		IDPSSODescriptors: []saml.IDPSSODescriptor{{}},
	}
	ed.IDPSSODescriptors[0].ProtocolSupportEnumeration = "urn:oasis:names:tc:SAML:2.0:protocol"
	ed.IDPSSODescriptors[0].KeyDescriptors = []saml.KeyDescriptor{{
		Use: "signing",
		KeyInfo: saml.KeyInfo{
			X509Data: saml.X509Data{
				X509Certificates: []saml.X509Certificate{
					{Data: base64.StdEncoding.EncodeToString(signer.cert.Raw)},
				},
			},
		},
	}}
	ed.IDPSSODescriptors[0].SingleSignOnServices = []saml.Endpoint{{
		Binding:  saml.HTTPRedirectBinding,
		Location: ssoURL,
	}}
	out, err := xml.MarshalIndent(ed, "", "  ")
	if err != nil {
		t.Fatalf("marshal IdP metadata: %v", err)
	}
	return out
}

// newTestSP builds an SPAuthenticator pinned to signer's cert, for an SP with
// the given entityID + acsURL, with a fixed clock at now.
func newTestSP(t *testing.T, signer *idpKeypair, idpEntityID, entityID, acsURL string, now time.Time) *SPAuthenticator {
	t.Helper()
	a, err := NewSPAuthenticator(SPConfig{
		Name:        "test-idp",
		EntityID:    entityID,
		ACSURL:      acsURL,
		IDPCert:     signer.certPEM(),
		IDPEntityID: idpEntityID,
	})
	if err != nil {
		t.Fatalf("NewSPAuthenticator: %v", err)
	}
	a.now = func() time.Time { return now }
	return a
}
