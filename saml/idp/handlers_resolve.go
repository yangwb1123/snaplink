package idp

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/crewjam/saml"

	"github.com/snaplink/sso"
)

// resolveSPClient scans the ClientStore for the registered SP whose
// saml_sp_entity_id matches issuer. O(n) over clients — noted; a SAML SP
// directory is small, and an index can replace this if it ever isn't. Returns
// errNoSPMatch when none matches (the caller collapses to saml_request_invalid,
// no SP-enumeration oracle).
func (h *Handlers) resolveSPClient(ctx context.Context, issuer string) (*sso.Client, error) {
	if issuer == "" {
		return nil, errNoSPMatch
	}
	clients, err := h.deps.ClientStore.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range clients {
		if c.Attributes[AttrSPEntityID] == issuer {
			return c, nil
		}
	}
	return nil, errNoSPMatch
}

// signerForClient resolves the per-tenant signing key for spClient through the
// SAME IssuerForClient path metadata uses, returning a CACHED AssertionSigner
// (one per signing-key kid, so metadata + every assertion embed a byte-
// identical self-signed cert — see the signerCache field doc). It FAILS CLOSED:
// if the issuer can't be resolved, or its TokenIssuer can't expose a stdlib
// crypto.Signer (or it's an Ed25519 key), the error propagates and the caller
// returns saml_assertion_failed — NEVER a fallback to a different tenant's key
// (per-tenant key isolation, AGENTS.md §2).
func (h *Handlers) signerForClient(spClient *sso.Client) (*AssertionSigner, error) {
	_, issuer, err := h.deps.IssuerForClient(spClient)
	if err != nil {
		return nil, err
	}
	cs, ok := issuer.(cryptoSignerIssuer)
	if !ok {
		return nil, ErrUnsupportedSigningKey
	}
	signer, pub, kid := cs.CryptoSigner()

	// Cache hit: reuse the existing signer (and its already-built cert) for this
	// key. The kid is a stable per-key fingerprint, so two clients in the same
	// tenant (sharing a key) get the same cached signer, and a rotation (new
	// kid) gets a fresh one.
	if kid != "" {
		h.signerMu.RLock()
		cached := h.signerCache[kid]
		h.signerMu.RUnlock()
		if cached != nil {
			return cached, nil
		}
	}

	as, err := NewAssertionSigner(signer, pub, kid, h.entityID())
	if err != nil {
		return nil, err
	}
	if kid != "" {
		h.signerMu.Lock()
		// Re-check under the write lock (another goroutine may have populated
		// it); first writer wins so the cert stays stable.
		if existing := h.signerCache[kid]; existing != nil {
			as = existing
		} else {
			h.signerCache[kid] = as
		}
		h.signerMu.Unlock()
	}
	return as, nil
}

// metadataSigner resolves the signer the /saml/metadata endpoint publishes the
// KeyDescriptor cert from, returning whether that key can drive XML-DSig
// (canSign). It is a SUPERSET of signerForClient that tolerates an Ed25519
// issuer for the cert ONLY:
//
//   - RSA / ECDSA → the SAME cached XML-DSig-capable AssertionSigner
//     signerForClient returns (so the metadata cert byte-matches assertions and
//     the cache stays shared), canSign=true.
//   - Ed25519 → a cert-only AssertionSigner (canSign=false), so the metadata
//     endpoint can still publish the key + serve UNSIGNED metadata instead of
//     500ing. The assertion / SLO paths keep using signerForClient, which still
//     fails closed for Ed25519 — this does NOT let an Ed25519 key sign anything.
//
// A resolution failure other than the Ed25519 case (unresolvable issuer, a
// TokenIssuer that can't expose a stdlib crypto.Signer, a non-P256 ECDSA curve)
// still propagates an error (the caller 500s), preserving fail-closed behavior.
func (h *Handlers) metadataSigner(spClient *sso.Client) (signer *AssertionSigner, canSign bool, err error) {
	// Try the XML-DSig-capable path first (RSA/ECDSA). On success the cert
	// matches what assertions embed.
	if as, serrr := h.signerForClient(spClient); serrr == nil {
		return as, true, nil
	} else if !errors.Is(serrr, ErrUnsupportedSigningKey) {
		// A genuine resolution failure (unresolvable issuer, wrong curve, no
		// crypto.Signer) — fail closed, do NOT silently fall back.
		return nil, false, serrr
	}

	// ErrUnsupportedSigningKey: the key can't XML-DSig. Distinguish an Ed25519
	// issuer (publish cert + serve unsigned) from a truly unresolvable signer.
	_, issuer, ierr := h.deps.IssuerForClient(spClient)
	if ierr != nil {
		return nil, false, ierr
	}
	cs, ok := issuer.(cryptoSignerIssuer)
	if !ok {
		return nil, false, ErrUnsupportedSigningKey
	}
	sgn, pub, kid := cs.CryptoSigner()
	if sgn == nil {
		return nil, false, ErrUnsupportedSigningKey
	}
	if _, isEd := pub.(ed25519.PublicKey); !isEd {
		// Not Ed25519 yet still unsupported (e.g. a non-P256 ECDSA curve): fail
		// closed rather than publish a cert we'd never sign assertions with.
		return nil, false, ErrUnsupportedSigningKey
	}
	certOnly, cerr := newCertOnlyAssertionSigner(sgn, pub, kid, h.entityID())
	if cerr != nil {
		return nil, false, cerr
	}
	return certOnly, false, nil
}

// acsAllowed reports whether acsURL is in the SP client's registered ACS
// allowlist (AttrSPACSURLs, pipe-delimited). An empty allowlist denies ALL —
// a SAML SP MUST register at least one ACS, so a missing/empty list is a
// misconfiguration that rejects (never an open redirect). Empty acsURL also
// denies. Comparison is exact (no normalization — the registered value is the
// source of truth; an SP must register the exact ACS it uses).
func acsAllowed(spClient *sso.Client, acsURL string) bool {
	if acsURL == "" {
		return false
	}
	raw := spClient.Attributes[AttrSPACSURLs]
	if raw == "" {
		return false
	}
	for _, candidate := range strings.Split(raw, acsURLDelimiter) {
		if strings.TrimSpace(candidate) == acsURL {
			return true
		}
	}
	return false
}

// firstACS returns the SP's first registered ACS URL (used when an AuthnRequest
// omits AssertionConsumerServiceURL — the SP delegates the choice to its
// registered default). Empty when the SP registered none.
func firstACS(spClient *sso.Client) string {
	raw := spClient.Attributes[AttrSPACSURLs]
	for _, candidate := range strings.Split(raw, acsURLDelimiter) {
		if v := strings.TrimSpace(candidate); v != "" {
			return v
		}
	}
	return ""
}

// firstSLO returns the SP's first registered SLO URL (the destination for the
// LogoutResponse the IdP returns after a SP-initiated SLO). It is taken from
// the SP's REGISTERED AttrSPSLOUrls (server config), NEVER from the inbound
// LogoutRequest — a request-supplied response destination would be a
// logout-response-injection / open-redirect vector (the SLO analogue of the
// ACS allowlist). Empty when the SP registered no SLO URL.
func firstSLO(spClient *sso.Client) string {
	raw := spClient.Attributes[AttrSPSLOUrls]
	for _, candidate := range strings.Split(raw, acsURLDelimiter) {
		if v := strings.TrimSpace(candidate); v != "" {
			return v
		}
	}
	return ""
}

// spSLOBinding returns the SP's registered SLO fan-out binding (AttrSPSLOBinding),
// normalized to BindingRedirect (the default) or BindingPost. An unrecognized or
// absent value yields BindingRedirect — the safe, real-IdP-default form.
func spSLOBinding(spClient *sso.Client) string {
	switch strings.ToLower(strings.TrimSpace(spClient.Attributes[AttrSPSLOBinding])) {
	case BindingPost:
		return BindingPost
	default:
		return BindingRedirect
	}
}

// spSLOChannel returns the SP's registered SLO channel (AttrSPSLOChannel),
// normalized to ChannelBackchannel (the default) or ChannelFrontchannel. An
// unrecognized or absent value yields ChannelBackchannel — back-compat: every SP
// fans out server-to-server unless it explicitly opts into the front-channel
// browser-redirect chain.
func spSLOChannel(spClient *sso.Client) string {
	switch strings.ToLower(strings.TrimSpace(spClient.Attributes[AttrSPSLOChannel])) {
	case ChannelFrontchannel:
		return ChannelFrontchannel
	default:
		return ChannelBackchannel
	}
}

// sloAllowed reports whether sloURL is in the SP client's registered SLO
// allowlist (AttrSPSLOUrls, pipe-delimited). Mirrors acsAllowed exactly: an
// empty allowlist or empty URL denies; comparison is exact. Used to refuse
// sending a LogoutResponse to anywhere the SP did not pre-register.
func sloAllowed(spClient *sso.Client, sloURL string) bool {
	if sloURL == "" {
		return false
	}
	raw := spClient.Attributes[AttrSPSLOUrls]
	if raw == "" {
		return false
	}
	for _, candidate := range strings.Split(raw, acsURLDelimiter) {
		if strings.TrimSpace(candidate) == sloURL {
			return true
		}
	}
	return false
}

// noStore stamps the credential-endpoint cache headers (RFC 6749 §5.1) on every
// path of /saml/sso + /saml/sso/finish, BEFORE any branch — a cached cross-user
// SAML response (success or error) would be catastrophic.
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

// writeError emits ONLY {"error":<code>} as JSON (oracle-safe: no cause
// detail). Used for the IdP's request/assertion failure paths.
func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set(sso.HeaderContentType, sso.ContentTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{sso.KeyError: code})
}

// parseAuthnRequest decodes + XXE-validates + unmarshals a wire SAMLRequest
// into a crewjam AuthnRequest. redirectBinding selects raw-DEFLATE (GET) vs
// plain base64 (POST). Every failure returns errRequestInvalid (collapsed).
func parseAuthnRequest(samlRequest string, redirectBinding bool) (*saml.AuthnRequest, []byte, error) {
	raw, err := decodeAuthnRequest(samlRequest, redirectBinding)
	if err != nil {
		return nil, nil, errRequestInvalid
	}
	// XXE / entity-expansion / round-trip safety BEFORE unmarshal (the same
	// validator crewjam runs).
	if err := validateXMLRoundTrip(raw); err != nil {
		return nil, nil, errRequestInvalid
	}
	var req saml.AuthnRequest
	if err := xmlUnmarshalStrict(raw, &req); err != nil {
		return nil, nil, errRequestInvalid
	}
	return &req, raw, nil
}

// parseLogoutRequest decodes + XXE-validates + unmarshals a wire SAMLRequest
// into a crewjam LogoutRequest, returning the request struct AND the raw XML
// (needed to validate the enveloped XML-DSig over the exact received bytes).
// redirectBinding selects raw-DEFLATE (GET) vs plain base64 (POST). Every
// failure returns errRequestInvalid (collapsed, oracle-safe). This is the SLO
// analogue of parseAuthnRequest — crewjam v0.5.1 exposes no IdP-side
// LogoutRequest parser, so we decode through the same hardened pipeline.
func parseLogoutRequest(samlRequest string, redirectBinding bool) (*saml.LogoutRequest, []byte, error) {
	raw, err := decodeAuthnRequest(samlRequest, redirectBinding)
	if err != nil {
		return nil, nil, errRequestInvalid
	}
	if err := validateXMLRoundTrip(raw); err != nil {
		return nil, nil, errRequestInvalid
	}
	var req saml.LogoutRequest
	if err := xmlUnmarshalStrict(raw, &req); err != nil {
		return nil, nil, errRequestInvalid
	}
	return &req, raw, nil
}
