package idp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"

	"github.com/crewjam/saml"
)

// MetadataDoc is the rendered IdP EntityDescriptor plus its strong ETag,
// computed together so the HTTP layer can serve a stable, conditionally
// cacheable document.
type MetadataDoc struct {
	XML  []byte
	ETag string // strong validator: "<base64url(sha256(xml)[:8])>"
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
//
// The descriptor advertises ONLY a signing key (this IdP signs assertions; it
// does not publish an encryption key — assertion encryption to the SP is a
// later phase) and the HTTP-Redirect SSO binding (SP-initiated). The ETag is a
// sha256 prefix over the exact bytes, so an unchanged key + URLs yield a
// stable validator across requests and process restarts.
func GenerateMetadata(signer *AssertionSigner, entityID, ssoURL string) (*MetadataDoc, error) {
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

	body, err := xml.MarshalIndent(ed, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("saml/idp: marshal metadata: %w", err)
	}
	// Prepend the XML declaration so strict metadata consumers accept it.
	out := append([]byte(xml.Header), body...)

	sum := sha256.Sum256(out)
	etag := `"` + base64.RawURLEncoding.EncodeToString(sum[:8]) + `"`

	return &MetadataDoc{XML: out, ETag: etag}, nil
}
