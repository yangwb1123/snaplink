package idp

import (
	"net/http"
	"strconv"
	"time"

	"github.com/snaplink/sso"
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

	signer, err := h.signerForClient(client)
	if err != nil {
		// The resolved tenant's key can't drive XML-DSig (e.g. Ed25519) or is
		// unresolvable — the IdP can't publish a usable signing cert. Fail
		// closed with the IdP-internal code (NOT a request fault).
		h.deps.Logger.Error("saml/idp: metadata signer resolution failed", "error", err)
		writeError(w, http.StatusInternalServerError, sso.ErrSAMLAssertionFailed)
		return
	}

	doc, err := GenerateMetadata(signer, h.entityID(), h.ssoURL())
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
