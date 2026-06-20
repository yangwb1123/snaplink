package idp

import (
	"net/http"
	"strconv"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
)

// defaultMetadataTTL is the Cache-Control max-age on /saml/metadata when
// Deps.MetadataTTL is unset. Metadata changes only on a signing-key rotation,
// so an hour is a safe cacheable default (an SP re-fetches at most hourly).
const defaultMetadataTTL = time.Hour

// Metadata handles GET /saml/metadata — the IdP EntityDescriptor.
//
// The published signing cert wraps the per-tenant signing key resolved through
// the SAME deps.IssuerForClient path the finish handler signs assertions with
// (blueprint Risk 3: an SP must validate assertions against the cert it fetched
// from metadata, so the two MUST resolve the identical key). The endpoint
// selects the tenant key by:
//
//   - ?client_id=<id>     → that SP client's tenant key, OR
//   - ?sp_entity_id=<eid> → the SP registered under that SAML entity id, OR
//   - (neither)           → the server's DEFAULT issuer key.
//
// Unlike /saml/sso + /saml/sso/finish, metadata is PUBLIC + cacheable
// (Cache-Control: public, max-age + strong ETag + If-None-Match → 304) — it
// carries only public-key material an SP needs to trust this IdP.
func (h *Handlers) Metadata(w http.ResponseWriter, r *http.Request) {
	// Resolve which tenant's signing key to publish (default issuer when no
	// selector is given). A selector that names an unknown client/SP is a
	// client error (the operator asked for metadata of a non-existent SP).
	client, err := h.metadataClient(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
		return
	}

	signer, canSign, err := h.metadataSigner(client)
	if err != nil {
		// The resolved tenant's key is unresolvable / unusable for the
		// KeyDescriptor cert (and is not the Ed25519 graceful-fallback case the
		// resolver handles internally) — the IdP can't publish usable metadata.
		// Fail closed with the IdP-internal code (NOT a request fault).
		h.deps.Logger.Error("saml/idp: metadata signer resolution failed", "error", err)
		writeError(w, http.StatusInternalServerError, sso.ErrSAMLAssertionFailed)
		return
	}

	// Sign the metadata only when (a) the operator opted in AND (b) the resolved
	// key can drive XML-DSig. An Ed25519 issuer (goxmldsig has no EdDSA method)
	// gracefully falls back to UNSIGNED metadata + a log — the endpoint stays
	// available rather than 500ing, mirroring that the assertion path simply
	// cannot use such a key.
	sign := h.deps.SignMetadata && canSign
	if h.deps.SignMetadata && !canSign {
		h.deps.Logger.Info("saml/idp: SignMetadata requested but signing key cannot drive XML-DSig (Ed25519); serving UNSIGNED metadata", "kid", signer.KeyID())
	}

	doc, err := h.metadataDoc(signer, sign)
	if err != nil {
		h.deps.Logger.Error("saml/idp: generate metadata failed", "error", err)
		writeError(w, http.StatusInternalServerError, sso.ErrSAMLAssertionFailed)
		return
	}

	// Conditional request: an unchanged key + URLs yield the same ETag.
	w.Header().Set("ETag", doc.ETag)
	if match := r.Header.Get("If-None-Match"); match != "" && match == doc.ETag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	ttl := h.deps.MetadataTTL
	if ttl <= 0 {
		ttl = defaultMetadataTTL
	}
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(int(ttl.Seconds())))
	w.Header().Set(sso.HeaderContentType, "application/samlmetadata+xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(doc.XML)
}

// metadataDoc renders the EntityDescriptor for signer, memoized per (kid, sign).
// The signed render is non-deterministic for ECDSA (random k), so caching keeps
// the served bytes — and thus the ETag — STABLE across requests (preserving the
// If-None-Match → 304 path); see the metadataCache field doc. A rotation (new
// kid) misses the cache and renders fresh. An empty kid (an issuer that exposes
// none) is rendered fresh each call rather than risk colliding distinct keys
// under one empty cache key — mirroring the signerCache's `if kid != ""`
// discipline.
func (h *Handlers) metadataDoc(signer *AssertionSigner, sign bool) (*MetadataDoc, error) {
	kid := signer.KeyID()
	key := metadataCacheKey(kid, sign)
	if kid != "" {
		h.metadataMu.RLock()
		cached := h.metadataCache[key]
		h.metadataMu.RUnlock()
		if cached != nil {
			return cached, nil
		}
	}

	doc, err := GenerateMetadata(signer, h.entityID(), h.ssoURL(), sign)
	if err != nil {
		return nil, err
	}

	if kid != "" {
		h.metadataMu.Lock()
		// First writer wins so the cached bytes (and the non-deterministic ECDSA
		// signature) stay stable for this key.
		if existing := h.metadataCache[key]; existing != nil {
			doc = existing
		} else {
			h.metadataCache[key] = doc
		}
		h.metadataMu.Unlock()
	}
	return doc, nil
}

// metadataCacheKey composes the (kid, signed) cache key. The signed flag is part
// of the key so the signed + unsigned renders of the same key never alias.
func metadataCacheKey(kid string, sign bool) string {
	if sign {
		return kid + "|signed"
	}
	return kid + "|unsigned"
}

// metadataClient resolves the SP client whose tenant key metadata should
// publish, from ?client_id= or ?sp_entity_id=. Returns (nil, nil) when neither
// is set (→ default issuer). Returns an error when a selector names an unknown
// client/SP.
func (h *Handlers) metadataClient(r *http.Request) (*sso.Client, error) {
	if id := r.URL.Query().Get(sso.KeyClientID); id != "" {
		return h.deps.ClientStore.Get(r.Context(), id)
	}
	if eid := r.URL.Query().Get("sp_entity_id"); eid != "" {
		return h.resolveSPClient(r.Context(), eid)
	}
	return nil, nil
}
