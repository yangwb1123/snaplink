package idp

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"io"

	xrv "github.com/mattermost/xml-roundtrip-validator"
)

// maxInflatedRequestBytes caps how many bytes we read out of a DEFLATEd
// SAMLRequest. A malicious SP could craft a tiny compressed payload that
// inflates to gigabytes (a decompression bomb); bounding the inflate at 1 MiB
// (an AuthnRequest is a few KiB) refuses that without affecting any real
// request. This is the same hardening crewjam applies in its un-exported
// newSaferFlateReader.
const maxInflatedRequestBytes = 1 << 20 // 1 MiB

// randHex returns a 16-byte (128-bit) hex string for SAML element IDs
// (Response/Assertion ID attributes). crypto/rand-backed so IDs are
// unguessable; hex keeps them XML-NCName-safe (a leading letter is prepended
// by the caller via the "id-" prefix).
func randHex() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// decodeAuthnRequest decodes a wire SAMLRequest into its raw XML bytes. For the
// HTTP-Redirect binding the value is base64(raw-DEFLATE(xml)); for HTTP-POST it
// is base64(xml). We try inflate first (Redirect, the common SP-initiated
// binding) and fall back to treating the base64 payload as already-plain XML
// (POST). The inflate is bounded against a decompression bomb.
//
// Returns the raw XML; the caller runs the XXE-safe round-trip validator +
// xml.Unmarshal. A decode failure collapses to the caller's oracle-safe
// saml_request_invalid.
func decodeAuthnRequest(samlRequest string, redirectBinding bool) ([]byte, error) {
	compressed, err := base64.StdEncoding.DecodeString(samlRequest)
	if err != nil {
		return nil, err
	}
	if redirectBinding {
		return inflateBounded(compressed)
	}
	return compressed, nil
}

// inflateBounded raw-inflates b with a hard output cap (decompression-bomb
// defense). flate.NewReader handles the raw DEFLATE stream SAML's HTTP-Redirect
// binding uses (RFC: no zlib header).
func inflateBounded(b []byte) ([]byte, error) {
	fr := flate.NewReader(bytes.NewReader(b))
	defer func() { _ = fr.Close() }()
	// LimitReader caps the inflated size; io.ReadAll over it never allocates
	// more than the cap +1 sentinel byte.
	out, err := io.ReadAll(io.LimitReader(fr, maxInflatedRequestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxInflatedRequestBytes {
		return nil, errInflateTooLarge
	}
	return out, nil
}

// validateXMLRoundTrip runs the XXE/round-trip safety check (the same
// mattermost validator crewjam uses) over raw XML BEFORE encoding/xml
// unmarshals it. It rejects the entity-expansion / namespace-confusion vectors
// the stdlib decoder would otherwise be lenient about. Returns nil when safe.
func validateXMLRoundTrip(raw []byte) error {
	return xrv.Validate(bytes.NewReader(raw))
}

// xmlUnmarshalStrict unmarshals raw into v with the stdlib decoder in strict
// mode. encoding/xml never resolves external DTDs/entities (no network/file
// fetch), so combined with the round-trip validator above this is the same
// XXE-safe parse crewjam performs. Strict=true refuses malformed/overlapping
// tags rather than silently recovering.
func xmlUnmarshalStrict(raw []byte, v any) error {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = true
	return dec.Decode(v)
}
