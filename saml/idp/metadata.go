package idp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
)

// MetadataDoc is the rendered IdP EntityDescriptor plus its strong ETag,
// computed together so the HTTP layer can serve a stable, conditionally
// cacheable document.
type MetadataDoc struct {
	XML  []byte
	ETag string // strong validator: "<base64url(sha256(kid|signed|xml)[:8])>"
}

// GenerateMetadata renders this server's IdP EntityDescriptor as SAML metadata
// XML. The signing KeyDescriptor wraps signer's self-signed certificate — the
// SAME cert (over the SAME per-tenant JWKS public key) that signs assertions,
// because signer was resolved through the IDENTICAL deps.IssuerForClient path
// the finish handler uses (blueprint Risk 3: metadata + signing MUST agree, or
// an SP rejects assertions it can't match to the advertised cert).
//
//   - entityID is the IdP's SAML entity identifier (Issuer + "/saml").
//   - ssoURL is the absolute HTTP-Redirect SingleSignOnService location
//     (the public /saml/sso URL), where SP AuthnRequests arrive.
//   - sign, when true, wraps the EntityDescriptor in an enveloped XML-DSig
//     (exclusive C14N, SHA-256) produced through signer's SigningContext — the
//     SAME path that enveloped-signs assertions — so a consumer doing
//     automated metadata refresh (Shibboleth federations, strict SPs) can
//     validate the metadata signature against the cert in this very document's
//     KeyDescriptor (no extra trust anchor). false ⇒ the metadata is UNSIGNED
//     and byte-identical to the historical output. The caller MUST pass false
//     when signer cannot drive XML-DSig (an Ed25519 issuer — goxmldsig has no
//     EdDSA signature method); SignatureMethod() == "" reports that.
//
// The descriptor advertises ONLY a signing key (this IdP signs assertions; it
// does not publish an encryption key — assertion encryption to the SP is a
// later phase) and the HTTP-Redirect SSO binding (SP-initiated). The ETag is a
// sha256 prefix that folds in the signing-key kid + the signed flag (so it
// changes on a key rotation AND when toggling signed/unsigned), then the body.
// Folding the kid + flag (not hashing the body alone) keeps the ETag STABLE for
// a given key even though an ECDSA XML-DSig SignatureValue is non-deterministic
// (random k) — the caller caches the rendered doc per (kid, signed) so the same
// bytes (and thus the same ETag) are served across requests, preserving the
// If-None-Match → 304 conditional-request path for the signed ECDSA case too.
func GenerateMetadata(signer *AssertionSigner, entityID, ssoURL string, sign bool) (*MetadataDoc, error) {
	if signer == nil {
		return nil, ErrUnsupportedSigningKey
	}
	cert, err := signer.Certificate()
	if err != nil {
		return nil, err
	}
	certB64 := base64.StdEncoding.EncodeToString(cert.Raw)

	ed := &saml.EntityDescriptor{
		EntityID: entityID,
		IDPSSODescriptors: []saml.IDPSSODescriptor{
			{
				SSODescriptor: saml.SSODescriptor{
					RoleDescriptor: saml.RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors: []saml.KeyDescriptor{
							{
								Use: "signing",
								KeyInfo: saml.KeyInfo{
									X509Data: saml.X509Data{
										X509Certificates: []saml.X509Certificate{
											{Data: certB64},
										},
									},
								},
							},
						},
					},
					// Advertise the NameID formats this IdP can mint. emailAddress
					// is the interoperable default (the SSO subject is an
					// email-shaped user id); persistent/transient are offered for
					// SPs that request them via NameIDPolicy.
					NameIDFormats: []saml.NameIDFormat{
						saml.NameIDFormat(string(saml.EmailAddressNameIDFormat)),
						saml.NameIDFormat(string(saml.PersistentNameIDFormat)),
						saml.NameIDFormat(string(saml.TransientNameIDFormat)),
					},
				},
				// SP-initiated SSO over HTTP-Redirect (the AuthnRequest binding
				// the /saml/sso handler decodes). HTTP-POST receipt of
				// AuthnRequests can be added later; the assertion always returns
				// over HTTP-POST to the SP's ACS.
				SingleSignOnServices: []saml.Endpoint{
					{
						Binding:  saml.HTTPRedirectBinding,
						Location: ssoURL,
					},
				},
			},
		},
	}

	var out []byte
	if sign {
		out, err = renderSignedMetadata(ed, signer)
	} else {
		out, err = renderUnsignedMetadata(ed)
	}
	if err != nil {
		return nil, err
	}

	// ETag input: kid | signed-flag | body. Folding the kid + flag guarantees a
	// rotation (new kid → new cert → new signer) and a signed/unsigned toggle
	// each move the validator, independent of any body-hash coincidence.
	h := sha256.New()
	_, _ = h.Write([]byte(signer.KeyID()))
	if sign {
		_, _ = h.Write([]byte{1})
	} else {
		_, _ = h.Write([]byte{0})
	}
	_, _ = h.Write(out)
	sum := h.Sum(nil)
	etag := `"` + base64.RawURLEncoding.EncodeToString(sum[:8]) + `"`

	return &MetadataDoc{XML: out, ETag: etag}, nil
}

// renderUnsignedMetadata marshals the EntityDescriptor exactly as the historical
// path did (xml.MarshalIndent + the XML declaration prepended), so unsigned
// metadata is BYTE-IDENTICAL to pre-feature output.
func renderUnsignedMetadata(ed *saml.EntityDescriptor) ([]byte, error) {
	body, err := xml.MarshalIndent(ed, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("saml/idp: marshal metadata: %w", err)
	}
	// Prepend the XML declaration so strict metadata consumers accept it.
	return append([]byte(xml.Header), body...), nil
}

// renderSignedMetadata produces an EntityDescriptor wrapped in an enveloped
// XML-DSig, mirroring how response_builder.go signs the assertion: build the
// element, SignEnveloped it through the per-tenant signer's SigningContext, then
// serialize the signed element. WHY signed metadata: consumers doing automated
// metadata refresh (Shibboleth federations, strict SPs) require the IdP
// metadata to be signed; the signature is over THIS EntityDescriptor and
// validates against the cert in its OWN KeyDescriptor (the same per-tenant key
// the IdP signs assertions with), so a consumer trusts it with no extra anchor.
//
// goxmldsig references the signed element by its ID attribute (DefaultIdAttr ==
// "ID"); an EntityDescriptor with an empty ID would be referenced by URI=""
// (whole-document), which strict SAML consumers handle less uniformly than a
// fragment reference — so a stable ID is stamped before signing.
//
// SignEnveloped appends the <Signature> as the element's LAST child. The SAML
// metadata schema (saml-schema-metadata-2.0.xsd) sequences ds:Signature FIRST
// (before the role descriptors), so the Signature is repositioned to index 0.
// This is digest-safe: goxmldsig computes the Reference digest over the element
// WITHOUT the Signature, and the validating enveloped-signature transform
// locates + removes the <Signature> by a tree search regardless of its position
// (validate.go mapPathToElement/removeElementAtPath), so moving it does not
// touch the signed content.
func renderSignedMetadata(ed *saml.EntityDescriptor, signer *AssertionSigner) ([]byte, error) {
	ctx, err := signer.SigningContext()
	if err != nil {
		return nil, err
	}

	// Stamp a stable ID so goxmldsig emits a fragment Reference (URI="#<id>").
	// Derived from the cert fingerprint so it is deterministic per signing key
	// (stable across requests + restarts for a given key, distinct on rotation).
	cert, err := signer.Certificate()
	if err != nil {
		return nil, err
	}
	fp := sha256.Sum256(cert.Raw)
	ed.ID = "id-" + base64.RawURLEncoding.EncodeToString(fp[:16])

	// EntityDescriptor has no etree .Element() (only MarshalXML), so marshal to
	// bytes then parse into an etree element to hand goxmldsig.
	body, err := xml.Marshal(ed)
	if err != nil {
		return nil, fmt.Errorf("saml/idp: marshal metadata for signing: %w", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(body); err != nil {
		return nil, fmt.Errorf("saml/idp: parse metadata for signing: %w", err)
	}
	root := doc.Root()
	if root == nil {
		return nil, fmt.Errorf("saml/idp: metadata has no root element")
	}

	signedEl, err := ctx.SignEnveloped(root)
	if err != nil {
		return nil, fmt.Errorf("saml/idp: sign metadata: %w", err)
	}
	moveSignatureFirst(signedEl)

	outDoc := etree.NewDocument()
	outDoc.SetRoot(signedEl)
	// Match the unsigned path's presentation: an XML declaration prepended below.
	// (Indentation is deliberately NOT applied to the signed element — added
	// whitespace text nodes between elements are preserved by exclusive C14N and
	// would have to be signed; serializing the exact signed element keeps served
	// bytes == signed bytes. etree.WriteToBytes emits no declaration of its own.)
	raw, err := outDoc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("saml/idp: serialize signed metadata: %w", err)
	}
	return append([]byte(xml.Header), raw...), nil
}

// moveSignatureFirst relocates the enveloped <Signature> (appended by
// SignEnveloped as the last child) to the FIRST child position, the order the
// SAML metadata XSD mandates for ds:Signature on an EntityDescriptor. Safe per
// the digest/transform reasoning in renderSignedMetadata. No-op if no Signature
// child is present.
//
// It removes by INDEX (RemoveChildAt), not by token (RemoveChild): goxmldsig's
// SignEnveloped appends the Signature via a raw slice append without linking the
// element's Parent(), so etree's RemoveChild — which is a no-op when
// token.Parent() != el — would silently fail and leave a DUPLICATE Signature
// (one at the front from InsertChildAt, the original still at the end), breaking
// validation. RemoveChildAt sidesteps the parent-pointer check.
func moveSignatureFirst(el *etree.Element) {
	for i, child := range el.Child {
		ce, ok := child.(*etree.Element)
		if !ok || ce.Tag != "Signature" {
			continue
		}
		el.RemoveChildAt(i)
		el.InsertChildAt(0, ce)
		return
	}
}
