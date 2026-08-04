package oauth

import (
	"context"
	"net/http"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/middleware"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// RegisterDeps is what the RFC 7591/7592 Dynamic Client Registration
// handlers need from the server. *sso.Server satisfies it via accessor
// methods.
type RegisterDeps interface {
	DCRPolicy() *DCRPolicy
	ClientStoreAccessor() core.ClientStore
	SrvLogger() spi.Logger
	ResolveIssuer(ctx core.HandlerContext) string
	SetBearerChallenge(ctx core.HandlerContext, realm, errorCode, errorDesc string)
	RequireClientStore() error

	// CheckClientCreateQuota charges one client against the tenant's
	// resource quota before persistence. denied=true means a 403
	// quota_exceeded response was already written (the caller MUST stop);
	// charged=true means the caller MUST call ReleaseClientCreateQuota if
	// persistence subsequently fails. It is nil-safe on tenant-less clients
	// (open registration) and fails OPEN on a store outage — the same
	// governance posture as the session-creation quota gate.
	CheckClientCreateQuota(ctx core.HandlerContext, tenantID string) (charged, denied bool)

	// ReleaseClientCreateQuota compensates a CheckClientCreateQuota charge
	// when the client-store write fails afterward, so a transient store
	// error never permanently over-counts the tenant's client usage.
	ReleaseClientCreateQuota(ctx context.Context, tenantID string)

	// Auditor returns the audit Recorder so the self-service DCR
	// create/update/delete paths can record a credential-lifecycle event
	// (EventClientRegistered/Updated/Deleted) — the forensic counterpart to
	// the admin path's EventAdminClient* records. *sso.Server satisfies it;
	// the returned Recorder may be nil and Record is nil-safe, so callers
	// invoke it unconditionally.
	Auditor() *audit.Recorder

	// InvalidateClientCache evicts the client from the local ClientStoreCache AND
	// publishes a cluster KindClientChange so peer replicas converge before their
	// own cache TTL. The DCR register/update/delete handlers MUST call it after a
	// store write (mirroring the admin path) — without it, peers serve stale or
	// deleted client metadata (old redirect_uris, a deleted public client, an
	// un-rotated registration access token) until the cache expires. Nil-safe on
	// *sso.Server when no cache/bus is wired.
	InvalidateClientCache(clientID string)
}

// DCRRequest mirrors the RFC 7591 §2 client metadata subset this
// server understands. Unknown fields are ignored per §3.1 ("the
// authorization server MUST ignore values it does not understand").
type DCRRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	ClientName              string   `json:"client_name"`
	Scope                   string   `json:"scope"`
	Contacts                []string `json:"contacts"`
	TokenStrategy           string   `json:"token_strategy"`
	AllowedAuthenticators   []string `json:"allowed_authenticators"`
	AllowedResources        []string `json:"allowed_resources"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris"`
	TenantID                string   `json:"tenant_id"`
	RequirePKCE             bool     `json:"require_pkce"`
	JWKS                    *DCRJWKS `json:"jwks,omitempty"`
	TLSClientAuthSubjectDN  string   `json:"tls_client_auth_subject_dn,omitempty"`
	TLSClientAuthSANDNS     string   `json:"tls_client_auth_san_dns,omitempty"`
	TLSClientAuthSANEmail   string   `json:"tls_client_auth_san_email,omitempty"`
	TLSClientAuthSANURI     string   `json:"tls_client_auth_san_uri,omitempty"`

	// OIDC Core JWE response-encryption metadata (§2 / §5.3.2).
	IDTokenEncryptedResponseAlg  string `json:"id_token_encrypted_response_alg"`
	IDTokenEncryptedResponseEnc  string `json:"id_token_encrypted_response_enc"`
	UserinfoEncryptedResponseAlg string `json:"userinfo_encrypted_response_alg"`
	UserinfoEncryptedResponseEnc string `json:"userinfo_encrypted_response_enc"`
}

type DCRJWKS struct {
	Keys []core.JWK `json:"keys"`
}

// DCRResponse is the RFC 7591 §3.2.1 successful-registration body.
// Echoes every accepted metadata field plus the issued credentials,
// timestamps, and the RFC 7592 management URI / access token when
// the management endpoint is enabled.
type DCRResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	RegistrationAccessToken string   `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string   `json:"registration_client_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	ClientName              string   `json:"client_name,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	Contacts                []string `json:"contacts"`
	TokenStrategy           string   `json:"token_strategy,omitempty"`
	AllowedAuthenticators   []string `json:"allowed_authenticators,omitempty"`
	AllowedResources        []string `json:"allowed_resources,omitempty"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris,omitempty"`
	RequirePKCE             bool     `json:"require_pkce,omitempty"`
	TenantID                string   `json:"tenant_id"`
	JWKS                    *DCRJWKS `json:"jwks,omitempty"`
	TLSClientAuthSubjectDN  string   `json:"tls_client_auth_subject_dn,omitempty"`
	TLSClientAuthSANDNS     string   `json:"tls_client_auth_san_dns,omitempty"`
	TLSClientAuthSANEmail   string   `json:"tls_client_auth_san_email,omitempty"`
	TLSClientAuthSANURI     string   `json:"tls_client_auth_san_uri,omitempty"`

	IDTokenEncryptedResponseAlg  string `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenEncryptedResponseEnc  string `json:"id_token_encrypted_response_enc,omitempty"`
	UserinfoEncryptedResponseAlg string `json:"userinfo_encrypted_response_alg,omitempty"`
	UserinfoEncryptedResponseEnc string `json:"userinfo_encrypted_response_enc,omitempty"`
}

// validateDCRRequest adapts the wire DTO to DCRMetadata and runs the
// shared policy validation against the canonical grant set.
func validateDCRRequest(req *DCRRequest, policy *DCRPolicy) error {
	normalizeDCRDefaults(req)
	meta := &DCRMetadata{
		RedirectURIs:                 req.RedirectURIs,
		TokenEndpointAuthMethod:      req.TokenEndpointAuthMethod,
		GrantTypes:                   req.GrantTypes,
		ResponseTypes:                req.ResponseTypes,
		AllowedAuthenticators:        req.AllowedAuthenticators,
		HasJWKS:                      req.JWKS != nil && len(req.JWKS.Keys) > 0,
		TLSClientAuthSubjectDN:       req.TLSClientAuthSubjectDN,
		TLSClientAuthSANDNS:          req.TLSClientAuthSANDNS,
		TLSClientAuthSANEmail:        req.TLSClientAuthSANEmail,
		TLSClientAuthSANURI:          req.TLSClientAuthSANURI,
		IDTokenEncryptedResponseAlg:  req.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:  req.IDTokenEncryptedResponseEnc,
		UserinfoEncryptedResponseAlg: req.UserinfoEncryptedResponseAlg,
		UserinfoEncryptedResponseEnc: req.UserinfoEncryptedResponseEnc,
	}
	if err := ValidateDCRMetadata(meta, policy, core.SupportedGrants, core.GrantAuthorizationCode); err != nil {
		return err
	}
	// Copy back the canonical (enc-defaulted) values so the persisted
	// client carries the resolved pair.
	req.IDTokenEncryptedResponseAlg = meta.IDTokenEncryptedResponseAlg
	req.IDTokenEncryptedResponseEnc = meta.IDTokenEncryptedResponseEnc
	req.UserinfoEncryptedResponseAlg = meta.UserinfoEncryptedResponseAlg
	req.UserinfoEncryptedResponseEnc = meta.UserinfoEncryptedResponseEnc
	return nil
}

func normalizeDCRDefaults(req *DCRRequest) {
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic"
	}
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{core.GrantAuthorizationCode}
	}
	if len(req.ResponseTypes) == 0 && containsString(req.GrantTypes, core.GrantAuthorizationCode) {
		req.ResponseTypes = []string{"code"}
	}
}

// HandleRegister implements RFC 7591 Dynamic Client Registration.
// Opt-in via WithDynamicClientRegistration; without it /register
// returns 501.
//
// Auth gate: requires the configured initial access token (a
// pre-shared bearer the operator distributes) unless the policy's
// AllowOpenRegistration=true is set. Open registration is
// supported but discouraged — every public registration endpoint
// in the wild eventually gets used for resource exhaustion.
//
// Response per §3.2.1: 201 Created + the issued credentials +
// the echoed metadata. Public clients (token_endpoint_auth_method
// = "none") skip secret generation per §2.
func HandleRegister(d RegisterDeps, ctx core.HandlerContext) {
	// Credential-shaped body (secret + RAT) — no-store, same as /token.
	middleware.TokenNoStoreHeaders(ctx)
	policy := d.DCRPolicy()
	if policy == nil {
		ctx.JSON(http.StatusNotImplemented, core.ErrorBody(ErrRegistrationDisabled))
		return
	}
	if err := d.RequireClientStore(); err != nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrServerMisconfigured))
		return
	}
	if !authorizeRegistration(d, ctx, policy) {
		return
	}

	var req DCRRequest
	if err := ctx.Bind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBodyDesc(ErrInvalidClientMetadata, err.Error()))
		return
	}
	if err := validateDCRRequest(&req, policy); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBodyDesc(ErrInvalidClientMetadata, err.Error()))
		return
	}

	// Public clients ("none" auth method) skip secret issuance per RFC 7591 §2.
	public := req.TokenEndpointAuthMethod == "none"
	id, secret, regToken, ok := mintClientIdentity(d, ctx, public)
	if !ok {
		return
	}
	client := buildRegisteredClient(&req, policy, id, secret, regToken, public)
	if !persistRegisteredClient(d, ctx, client) {
		return
	}
	d.InvalidateClientCache(client.ID) // evict local + publish KindClientChange to peers
	// Forensic trail — recorded ONLY now that the store write succeeded.
	recordRegistrationCreated(d, ctx, policy, client.ID)
	ctx.JSON(http.StatusCreated, buildDCRResponse(&req, client, ctx, secret, regToken))
}

// persistRegisteredClient runs the quota-gated client-store write: charges
// the tenant's client quota, writes the record, and — if the write fails
// after a successful charge — releases the quota so a transient store error
// never permanently over-counts usage. Returns false when the response was
// already written (quota denied or persist failure).
func persistRegisteredClient(d RegisterDeps, ctx core.HandlerContext, client *core.Client) bool {
	charged, denied := d.CheckClientCreateQuota(ctx, client.TenantID)
	if denied {
		return false
	}
	if err := d.ClientStoreAccessor().Add(ctx.Request().Context(), client); err != nil {
		if charged {
			d.ReleaseClientCreateQuota(ctx.Request().Context(), client.TenantID)
		}
		d.SrvLogger().Error("dcr persist failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return false
	}
	return true
}

// HandleRegistrationGet implements RFC 7592 §2.1 — the client
// itself reads its current registration metadata. Auth: bearer
// matching the registration_access_token issued at /register.
func HandleRegistrationGet(d RegisterDeps, ctx core.HandlerContext) {
	middleware.TokenNoStoreHeaders(ctx)
	client, ok := authorizeRegistrationMgmt(d, ctx)
	if !ok {
		return
	}
	ctx.JSON(http.StatusOK, projectClientToDCRResponse(client, ctx))
}

// HandleRegistrationPut implements RFC 7592 §2.2 — the client
// itself updates its metadata. Auth: bearer matching the
// registration_access_token. Validation: same rules as POST
// /register; the client_secret stays unchanged across updates
// (rotation is a separate admin RPC). The registration_access_token
// is also preserved so the caller can keep managing the registration.
func HandleRegistrationPut(d RegisterDeps, ctx core.HandlerContext) {
	middleware.TokenNoStoreHeaders(ctx)
	client, ok := authorizeRegistrationMgmt(d, ctx)
	if !ok {
		return
	}

	var req DCRRequest
	if err := ctx.Bind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBodyDesc(ErrInvalidClientMetadata, err.Error()))
		return
	}
	if err := validateDCRRequest(&req, d.DCRPolicy()); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBodyDesc(ErrInvalidClientMetadata, err.Error()))
		return
	}

	// RFC 7592 §3.2: optionally rotate the registration_access_token on update.
	// Default-off preserves the stable-token behavior; when on, mint a fresh
	// token, persist it (hashed at rest by the store), and reveal the plaintext
	// once in the response. newRAT empty => keep the existing (already-hashed)
	// token unchanged.
	rotation, err := rotateRAT(d, client, BearerToken(ctx.Request()))
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}

	updated := buildUpdatedClient(&req, client, rotation)

	if err := d.ClientStoreAccessor().Update(ctx.Request().Context(), updated); err != nil {
		d.SrvLogger().Error("dcr update failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	d.InvalidateClientCache(updated.ID) // evict local + publish KindClientChange to peers
	// Recorded only AFTER an authorized bearer + successful write —
	// authorizeRegistrationMgmt already short-circuited every failed-bearer /
	// unknown-client path with an identical 401 (no event), so this never
	// fires on a rejection (anti-enumeration, §2).
	recordDCRLifecycle(d, ctx, audit.EventClientUpdated, updated.ID, "")
	resp := projectClientToDCRResponse(updated, ctx)
	// One-time reveal of the rotated token (the stored value is now hashed).
	// Without rotation the field stays omitted — GET/PUT never echo the RAT.
	if rotation.plaintext != "" {
		resp.RegistrationAccessToken = rotation.plaintext
	}
	ctx.JSON(http.StatusOK, resp)
}

// HandleRegistrationDelete implements RFC 7592 §2.3 — the client
// itself removes its registration. Auth: bearer matching the
// registration_access_token. Successful response: 204 No Content
// per §2.3.
func HandleRegistrationDelete(d RegisterDeps, ctx core.HandlerContext) {
	middleware.TokenNoStoreHeaders(ctx)
	client, ok := authorizeRegistrationMgmt(d, ctx)
	if !ok {
		return
	}
	if err := d.ClientStoreAccessor().Delete(ctx.Request().Context(), client.ID); err != nil {
		d.SrvLogger().Error("dcr delete failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	d.InvalidateClientCache(client.ID) // evict local + publish KindClientChange to peers
	// As with the update path: authorizeRegistrationMgmt gates this, so the
	// event records an authorized self-service deletion only — never a
	// failed-bearer probe (anti-enumeration, §2).
	recordDCRLifecycle(d, ctx, audit.EventClientDeleted, client.ID, "")
	ctx.ResponseWriter().WriteHeader(http.StatusNoContent)
}

// authorizeRegistrationMgmt is the shared auth + lookup gate for
// every RFC 7592 endpoint. Resolves the client by path param,
// constant-time compares the presented bearer against the stored
// registration_access_token, and writes the appropriate error
// response when checks fail.
//
// Returns (client, true) on success; on failure it has already
// written the response and returns (nil, false).
func authorizeRegistrationMgmt(d RegisterDeps, ctx core.HandlerContext) (*core.Client, bool) {
	if d.DCRPolicy() == nil {
		ctx.JSON(http.StatusNotImplemented, core.ErrorBody(ErrRegistrationDisabled))
		return nil, false
	}
	if err := d.RequireClientStore(); err != nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrServerMisconfigured))
		return nil, false
	}
	id := ctx.Param("client_id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrMissingClientID))
		return nil, false
	}
	client, err := d.ClientStoreAccessor().Get(ctx.Request().Context(), id)
	if err != nil {
		// 401 (not 404) because the resource is auth-gated; a 404
		// would let an unauthed caller probe for client_id existence.
		// The challenge stays identical across "unknown client",
		// "missing bearer", and "wrong bearer" to preserve the
		// anti-enumeration property the catch-all 401 enforces.
		d.SetBearerChallenge(ctx, d.ResolveIssuer(ctx), core.ErrInvalidToken, "Registration access token missing or invalid")
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidToken))
		return nil, false
	}
	bearer := BearerToken(ctx.Request())
	if bearer == "" || client.RegistrationAccessToken == "" {
		d.SetBearerChallenge(ctx, d.ResolveIssuer(ctx), core.ErrInvalidToken, "Registration access token missing or invalid")
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidToken))
		return nil, false
	}
	// The stored RegistrationAccessToken may be a bcrypt hash (written by
	// the store's Add path).  CompareClientSecret handles both cases while
	// keeping the same constant-time guarantee for the plaintext fallback.
	if !validRegistrationToken(client, bearer, time.Now()) {
		d.SetBearerChallenge(ctx, d.ResolveIssuer(ctx), core.ErrInvalidToken, "Registration access token missing or invalid")
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidToken))
		return nil, false
	}
	return client, true
}

func validRegistrationToken(client *core.Client, bearer string, now time.Time) bool {
	if security.CompareClientSecret(client.RegistrationAccessToken, bearer) {
		return true
	}
	return !client.RegistrationAccessTokenOverlapUntil.IsZero() &&
		now.Before(client.RegistrationAccessTokenOverlapUntil) &&
		security.CompareClientSecret(client.PreviousRegistrationAccessToken, bearer)
}

// recordDCRLifecycle writes one self-service DCR lifecycle audit event
// (EventClientRegistered/Updated/Deleted) AFTER a successful store write.
// The base event is built via audit.EventFromRequest so it inherits the
// same RequestID / trace / ActorIP / UserAgent + tenant/geo/region
// enrichment as every other HTTP-path event; clientID identifies the
// affected client; method (create-only) records the registration method via
// SetMeta — NEVER a direct e.Metadata assignment, which would clobber the
// enrichment (§2). Auditor() may be nil and Recorder.Record is nil-safe, so
// this is unconditional and a no-op when no recorder is wired. It is reached
// ONLY on the authorized success path; the failed-bearer / unknown-client
// 401s short-circuit earlier and emit nothing (anti-enumeration, §2).
func recordDCRLifecycle(d RegisterDeps, ctx core.HandlerContext, t audit.EventType, clientID, method string) {
	rec := d.Auditor()
	if rec == nil {
		return
	}
	e := audit.EventFromRequest(ctx)
	e.Type = t
	e.Outcome = audit.OutcomeSuccess
	e.ClientID = clientID
	audit.SetMeta(e, MetaKeyDCRMethod, method) // SetMeta skips an empty method
	rec.Record(ctx.Request().Context(), e)
}

// projectClientToDCRResponse builds an RFC 7591-shaped response from
// a stored Client. Re-used by GET/PUT — the registration_access_token
// is NOT re-emitted (RFC 7592 §2.1: server SHOULD NOT include it on
// reads; the original /register response is the only canonical
// distribution point).
func projectClientToDCRResponse(c *core.Client, ctx core.HandlerContext) DCRResponse {
	// c.Secret is a bcrypt hash after store.Add/RotateSecret — we MUST NOT
	// return the hash as client_secret (it would leak the hash and mislead
	// the client into presenting it as a credential).  RFC 7592 §2.1 says
	// the server SHOULD include client_secret; we satisfy the intent at the
	// only moment the plaintext is known (initial /register and RotateSecret
	// responses).  Subsequent GET/PUT responses omit it, which RFC 7592 §2.1
	// also permits ("SHOULD" is not "MUST").
	return DCRResponse{
		ClientID:                c.ID,
		ClientSecretExpiresAt:   dcrClientSecretExpiry(c),
		RegistrationClientURI:   middleware.BaseURL(ctx.Request()) + PathRegister + "/" + c.ID,
		RedirectURIs:            c.RedirectURIs,
		GrantTypes:              append([]string(nil), c.GrantTypes...),
		ResponseTypes:           dcrAttributeList(c.Attributes, dcrResponseTypesAttribute),
		Contacts:                dcrAttributeList(c.Attributes, dcrContactsAttribute),
		ClientName:              c.Name,
		Scope:                   JoinScope(c.AllowedScopes),
		TokenStrategy:           c.TokenStrategy,
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
		AllowedAuthenticators:   c.AllowedAuthenticators,
		AllowedResources:        c.AllowedResources,
		PostLogoutRedirectURIs:  c.PostLogoutRedirectURIs,
		RequirePKCE:             c.RequirePKCE,
		TenantID:                c.TenantID,
		JWKS:                    dcrJWKS(c.JWKS),
		TLSClientAuthSubjectDN:  c.TLSClientAuthSubjectDN,
		TLSClientAuthSANDNS:     c.TLSClientAuthSANDNS,
		TLSClientAuthSANEmail:   c.TLSClientAuthSANEmail,
		TLSClientAuthSANURI:     c.TLSClientAuthSANURI,

		IDTokenEncryptedResponseAlg:  c.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:  c.IDTokenEncryptedResponseEnc,
		UserinfoEncryptedResponseAlg: c.UserinfoEncryptedResponseAlg,
		UserinfoEncryptedResponseEnc: c.UserinfoEncryptedResponseEnc,
	}
}
