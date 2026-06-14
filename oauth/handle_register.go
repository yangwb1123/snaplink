package oauth

import (
	"net/http"
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/middleware"
	"github.com/snaplink/sso/security"
	"github.com/snaplink/sso/spi"
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

	// Auditor returns the audit Recorder so the self-service DCR
	// create/update/delete paths can record a credential-lifecycle event
	// (EventClientRegistered/Updated/Deleted) — the forensic counterpart to
	// the admin path's EventAdminClient* records. *sso.Server satisfies it;
	// the returned Recorder may be nil and Record is nil-safe, so callers
	// invoke it unconditionally.
	Auditor() *audit.Recorder
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

	// OIDC Core JWE response-encryption metadata (§2 / §5.3.2).
	IDTokenEncryptedResponseAlg  string `json:"id_token_encrypted_response_alg"`
	IDTokenEncryptedResponseEnc  string `json:"id_token_encrypted_response_enc"`
	UserinfoEncryptedResponseAlg string `json:"userinfo_encrypted_response_alg"`
	UserinfoEncryptedResponseEnc string `json:"userinfo_encrypted_response_enc"`
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
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	TokenStrategy           string   `json:"token_strategy,omitempty"`
	AllowedAuthenticators   []string `json:"allowed_authenticators,omitempty"`
	AllowedResources        []string `json:"allowed_resources,omitempty"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris,omitempty"`
	RequirePKCE             bool     `json:"require_pkce,omitempty"`

	IDTokenEncryptedResponseAlg  string `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenEncryptedResponseEnc  string `json:"id_token_encrypted_response_enc,omitempty"`
	UserinfoEncryptedResponseAlg string `json:"userinfo_encrypted_response_alg,omitempty"`
	UserinfoEncryptedResponseEnc string `json:"userinfo_encrypted_response_enc,omitempty"`
}

// validateDCRRequest adapts the wire DTO to DCRMetadata and runs the
// shared policy validation against the canonical grant set.
func validateDCRRequest(req *DCRRequest, policy *DCRPolicy) error {
	meta := &DCRMetadata{
		RedirectURIs:                 req.RedirectURIs,
		TokenEndpointAuthMethod:      req.TokenEndpointAuthMethod,
		GrantTypes:                   req.GrantTypes,
		ResponseTypes:                req.ResponseTypes,
		AllowedAuthenticators:        req.AllowedAuthenticators,
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
	// DCR responses ship client_secret + registration_access_token —
	// credential-shaped bodies that intermediaries must not cache.
	// Same RFC 6749 §5.1 pattern as /token.
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

	// Authentication gate. Initial-access-token takes precedence
	// when configured; AllowOpenRegistration is the explicit
	// escape hatch.
	if !policy.AllowOpenRegistration {
		if policy.InitialAccessToken == "" {
			ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrServerMisconfigured))
			return
		}
		if bearer := BearerToken(ctx.Request()); bearer != policy.InitialAccessToken {
			d.SetBearerChallenge(ctx, d.ResolveIssuer(ctx), core.ErrInvalidToken, "Initial access token missing or invalid")
			ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidToken))
			return
		}
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

	id, err := GenerateClientID()
	if err != nil {
		d.SrvLogger().Error("dcr id gen failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}

	// Public clients (no secret) per RFC 7591 §2 +
	// RFC 6749 §2.3 — the "none" auth method opts out of secret
	// issuance entirely. SPAs and mobile apps that hold no
	// confidential secret should request this.
	public := req.TokenEndpointAuthMethod == "none"
	secret := ""
	if !public {
		secret, err = GenerateClientSecret()
		if err != nil {
			d.SrvLogger().Error("dcr secret gen failed", "error", err)
			ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
			return
		}
	}

	// RFC 7592 §3: every newly-registered client gets a
	// registration_access_token so the client itself can later
	// GET/PUT/DELETE its own registration without operator
	// involvement. The token is bearer-shaped; deployments
	// storing clients on disk SHOULD hash it at rest.
	regToken, err := GenerateClientSecret()
	if err != nil {
		d.SrvLogger().Error("dcr reg-token gen failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}

	tokenStrategy := req.TokenStrategy
	if tokenStrategy == "" {
		tokenStrategy = policy.DefaultTokenStrategy
	}

	client := &core.Client{
		ID:                      id,
		Secret:                  secret,
		Name:                    req.ClientName,
		RedirectURIs:            append([]string(nil), req.RedirectURIs...),
		AllowedScopes:           SplitScope(req.Scope),
		AllowedAuthenticators:   append([]string(nil), req.AllowedAuthenticators...),
		TokenStrategy:           tokenStrategy,
		Active:                  policy.DefaultActive,
		TenantID:                req.TenantID,
		RequirePKCE:             req.RequirePKCE || public, // public clients always PKCE
		AllowedResources:        append([]string(nil), req.AllowedResources...),
		PostLogoutRedirectURIs:  append([]string(nil), req.PostLogoutRedirectURIs...),
		RegistrationAccessToken: regToken,

		IDTokenEncryptedResponseAlg:  req.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:  req.IDTokenEncryptedResponseEnc,
		UserinfoEncryptedResponseAlg: req.UserinfoEncryptedResponseAlg,
		UserinfoEncryptedResponseEnc: req.UserinfoEncryptedResponseEnc,
	}

	if err := d.ClientStoreAccessor().Add(ctx.Request().Context(), client); err != nil {
		d.SrvLogger().Error("dcr persist failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	// Forensic trail for the credential-lifecycle: a confidential client was
	// just minted (fresh secret + registration_access_token) on the public
	// /register path. Recorded ONLY now that the store write succeeded; the
	// registration method tells operators whether an initial-access-token or
	// open registration produced it.
	method := dcrMethodInitialAccessToken
	if policy.AllowOpenRegistration {
		method = dcrMethodOpen
	}
	recordDCRLifecycle(d, ctx, audit.EventClientRegistered, client.ID, method)

	now := time.Now().Unix()
	resp := DCRResponse{
		ClientID:                id,
		ClientSecret:            secret,
		ClientIDIssuedAt:        now,
		ClientSecretExpiresAt:   0, // 0 = never expires per RFC 7591 §3.2.1
		RegistrationAccessToken: regToken,
		RegistrationClientURI:   middleware.BaseURL(ctx.Request()) + PathRegister + "/" + id,
		RedirectURIs:            client.RedirectURIs,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		ClientName:              client.Name,
		Scope:                   req.Scope,
		Contacts:                req.Contacts,
		TokenStrategy:           client.TokenStrategy,
		AllowedAuthenticators:   client.AllowedAuthenticators,
		AllowedResources:        client.AllowedResources,
		PostLogoutRedirectURIs:  client.PostLogoutRedirectURIs,
		RequirePKCE:             client.RequirePKCE,

		IDTokenEncryptedResponseAlg:  client.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:  client.IDTokenEncryptedResponseEnc,
		UserinfoEncryptedResponseAlg: client.UserinfoEncryptedResponseAlg,
		UserinfoEncryptedResponseEnc: client.UserinfoEncryptedResponseEnc,
	}

	ctx.JSON(http.StatusCreated, resp)
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

	tokenStrategy := req.TokenStrategy
	if tokenStrategy == "" {
		tokenStrategy = client.TokenStrategy
	}

	// RFC 7592 §3.2: optionally rotate the registration_access_token on update.
	// Default-off preserves the stable-token behavior; when on, mint a fresh
	// token, persist it (hashed at rest by the store), and reveal the plaintext
	// once in the response. newRAT empty => keep the existing (already-hashed)
	// token unchanged.
	ratToStore := client.RegistrationAccessToken // existing hash, unchanged
	var newRAT string
	if d.DCRPolicy().RotateRegistrationAccessToken {
		t, err := GenerateClientSecret()
		if err != nil {
			d.SrvLogger().Error("dcr reg-token rotation gen failed", "error", err)
			ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
			return
		}
		newRAT = t
		ratToStore = t // plaintext; the store hashes it at rest on Update
	}

	updated := &core.Client{
		ID:                      client.ID,
		Secret:                  client.Secret, // unchanged
		RegistrationAccessToken: ratToStore,
		Active:                  client.Active,
		Name:                    req.ClientName,
		RedirectURIs:            append([]string(nil), req.RedirectURIs...),
		AllowedScopes:           SplitScope(req.Scope),
		AllowedAuthenticators:   append([]string(nil), req.AllowedAuthenticators...),
		TokenStrategy:           tokenStrategy,
		TenantID:                req.TenantID,
		RequirePKCE:             req.RequirePKCE || req.TokenEndpointAuthMethod == "none",
		AllowedResources:        append([]string(nil), req.AllowedResources...),
		PostLogoutRedirectURIs:  append([]string(nil), req.PostLogoutRedirectURIs...),

		IDTokenEncryptedResponseAlg:  req.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:  req.IDTokenEncryptedResponseEnc,
		UserinfoEncryptedResponseAlg: req.UserinfoEncryptedResponseAlg,
		UserinfoEncryptedResponseEnc: req.UserinfoEncryptedResponseEnc,
	}

	if err := d.ClientStoreAccessor().Update(ctx.Request().Context(), updated); err != nil {
		d.SrvLogger().Error("dcr update failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	// Recorded only AFTER an authorized bearer + successful write —
	// authorizeRegistrationMgmt already short-circuited every failed-bearer /
	// unknown-client path with an identical 401 (no event), so this never
	// fires on a rejection (anti-enumeration, §2).
	recordDCRLifecycle(d, ctx, audit.EventClientUpdated, updated.ID, "")
	resp := projectClientToDCRResponse(updated, ctx)
	// One-time reveal of the rotated token (the stored value is now hashed).
	// Without rotation the field stays omitted — GET/PUT never echo the RAT.
	if newRAT != "" {
		resp.RegistrationAccessToken = newRAT
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
	if !security.CompareClientSecret(client.RegistrationAccessToken, bearer) {
		d.SetBearerChallenge(ctx, d.ResolveIssuer(ctx), core.ErrInvalidToken, "Registration access token missing or invalid")
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidToken))
		return nil, false
	}
	return client, true
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
	audit.SetMeta(e, metaKeyDCRMethod, method) // SetMeta skips an empty method
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
		ClientID:               c.ID,
		ClientSecretExpiresAt:  0,
		RegistrationClientURI:  middleware.BaseURL(ctx.Request()) + PathRegister + "/" + c.ID,
		RedirectURIs:           c.RedirectURIs,
		ClientName:             c.Name,
		Scope:                  JoinScope(c.AllowedScopes),
		TokenStrategy:          c.TokenStrategy,
		AllowedAuthenticators:  c.AllowedAuthenticators,
		AllowedResources:       c.AllowedResources,
		PostLogoutRedirectURIs: c.PostLogoutRedirectURIs,
		RequirePKCE:            c.RequirePKCE,

		IDTokenEncryptedResponseAlg:  c.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:  c.IDTokenEncryptedResponseEnc,
		UserinfoEncryptedResponseAlg: c.UserinfoEncryptedResponseAlg,
		UserinfoEncryptedResponseEnc: c.UserinfoEncryptedResponseEnc,
	}
}
