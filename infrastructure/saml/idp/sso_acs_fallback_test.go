package idp

import (
	"crypto/x509"
	"net/http"
	"net/url"
	"strings"
	"testing"

	dsig "github.com/russellhaering/goxmldsig"
)

// TestSSO_NoACSInRequest_FallsBackToFirstRegistered proves that an AuthnRequest
// that OMITS AssertionConsumerServiceURL falls back to the SP's first REGISTERED
// ACS (firstACS) rather than rejecting — the SP delegated the choice to its
// registration. The fallback must still be a registered (allowlisted) URL.
func TestSSO_NoACSInRequest_FallsBackToFirstRegistered(t *testing.T) {
	t.Parallel()
	hh := newHarness(t, issuerRSA)

	// Build an AuthnRequest with an EMPTY ACS URL; the IdP should use spACSURL
	// (the SP's first registered ACS) and proceed to the login redirect.
	authnReq := makeAuthnRequest(t, spEntityID, "", "id-req-noacs")
	rec := hh.getSSO(authnReq)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (ACS fallback to first registered); body=%s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/auth/login?") {
		t.Fatalf("Location = %q, want /auth/login?...", loc)
	}
	if n := hh.h.pending.len(); n != 1 {
		t.Fatalf("pending count = %d, want 1 (the fallback ACS was accepted)", n)
	}
}

// TestVerifyRedirectSignature_UnsupportedSigAlg_Rejected proves the
// alg-allowlist-before-verify gate: a detached redirect signature whose SigAlg is
// a NON-allowlisted (here SHA-1) URI is rejected by x509SigAlgForSigAlgURI BEFORE
// any key/signature math runs — a downgrade attempt can't reach CheckSignature.
func TestVerifyRedirectSignature_UnsupportedSigAlg_Rejected(t *testing.T) {
	t.Parallel()
	spKey := newSPKeypair(t)

	// A well-formed redirect query but carrying a SHA-1 SigAlg (not allowlisted).
	const sha1SigAlg = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	rawQuery := "SAMLRequest=" + url.QueryEscape("anything") +
		"&SigAlg=" + url.QueryEscape(sha1SigAlg) +
		"&Signature=" + url.QueryEscape("AAAA")

	err := verifyRedirectSignature(spKey.cert, rawQuery, "SAMLRequest")
	if err == nil {
		t.Fatal("verifyRedirectSignature accepted a SHA-1 (non-allowlisted) SigAlg")
	}
	if !strings.Contains(err.Error(), "unsupported redirect SigAlg") {
		t.Fatalf("err = %v, want an unsupported-SigAlg rejection (alg allowlist)", err)
	}
}

// TestVerifyRedirectSignature_NilCert_And_MissingSig covers the two fail-closed
// guards: no trust-anchor cert, and a query with no SigAlg/Signature pair.
func TestVerifyRedirectSignature_NilCert_And_MissingSig(t *testing.T) {
	t.Parallel()
	if err := verifyRedirectSignature(nil, "SAMLRequest=x", "SAMLRequest"); err == nil {
		t.Fatal("nil cert accepted")
	}
	spKey := newSPKeypair(t)
	// Has the message param but no SigAlg/Signature ⇒ "not signed" rejection.
	if err := verifyRedirectSignature(spKey.cert, "SAMLRequest=x", "SAMLRequest"); err == nil {
		t.Fatal("unsigned redirect query accepted (must fail closed)")
	}
	// Missing the message param entirely.
	if err := verifyRedirectSignature(spKey.cert, "RelayState=x", "SAMLRequest"); err == nil {
		t.Fatal("query missing SAMLRequest accepted")
	}
}

// TestX509SigAlgForSigAlgURI_Mapping locks the SigAlg → x509 alg allowlist: the
// two asymmetric SHA-256 methods map; everything else (SHA-1, empty, garbage) is
// rejected so it can never reach CheckSignature.
func TestX509SigAlgForSigAlgURI_Mapping(t *testing.T) {
	t.Parallel()
	if a, ok := x509SigAlgForSigAlgURI(dsig.RSASHA256SignatureMethod); !ok || a != x509.SHA256WithRSA {
		t.Fatalf("RSA-SHA256 mapped to %v ok=%v, want SHA256WithRSA", a, ok)
	}
	if a, ok := x509SigAlgForSigAlgURI(dsig.ECDSASHA256SignatureMethod); !ok || a != x509.ECDSAWithSHA256 {
		t.Fatalf("ECDSA-SHA256 mapped to %v ok=%v, want ECDSAWithSHA256", a, ok)
	}
	for _, bad := range []string{
		"http://www.w3.org/2000/09/xmldsig#rsa-sha1", // SHA-1 downgrade
		"http://www.w3.org/2000/09/xmldsig#hmac-sha1",
		"",
		"not-a-uri",
	} {
		if _, ok := x509SigAlgForSigAlgURI(bad); ok {
			t.Fatalf("non-allowlisted SigAlg %q was accepted", bad)
		}
	}
}
