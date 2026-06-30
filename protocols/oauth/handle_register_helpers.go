package oauth

import (
	"net/http"
	"time"

	"github.com/snaplink/sso/interfaces/middleware"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
)

// recordRegistrationCreated writes the EventClientRegistered lifecycle event
// for a freshly minted confidential client on the /register path. The
// registration method (initial-access-token vs open) tells operators which
// gate produced it. Called ONLY after a successful store write — the
// failed-auth paths short-circuit earlier and emit nothing (anti-enumeration).
func recordRegistrationCreated(d RegisterDeps, ctx core.HandlerContext, policy *DCRPolicy, clientID string) {
	method := DCRMethodInitialAccessToken
	if policy.AllowOpenRegistration {
		method = DCRMethodOpen
	}
	recordDCRLifecycle(d, ctx, audit.EventClientRegistered, clientID, method)
}

// authorizeRegistration is the RFC 7591 §3.2.1 authentication gate for the
// open /register endpoint. Initial-access-token takes precedence when
// configured; AllowOpenRegistration is the explicit escape hatch. Returns
// true to continue; on rejection it has already written the response
// (500 ErrServerMisconfigured when no IAT is configured, or the identical
// anti-enumeration 401 invalid_token + Bearer challenge on a missing/wrong
// bearer) and returns false.
func authorizeRegistration(d RegisterDeps, ctx core.HandlerContext, policy *DCRPolicy) bool {
	if policy.AllowOpenRegistration {
		return true
	}
	if policy.InitialAccessToken == "" {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrServerMisconfigured))
		return false
	}
	if bearer := BearerToken(ctx.Request()); !security.CompareClientSecret(policy.InitialAccessToken, bearer) {
		d.SetBearerChallenge(ctx, d.ResolveIssuer(ctx), core.ErrInvalidToken, "Initial access token missing or invalid")
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidToken))
		return false
	}
	return true
}

// mintClientIdentity mints the client_id and (for confidential clients) the
// secret + registration_access_token, writing the 500 response and returning
// ok=false on any generation failure. Extracted to keep HandleRegister within
// the function-length budget.
func mintClientIdentity(d RegisterDeps, ctx core.HandlerContext, public bool) (id, secret, regToken string, ok bool) {
	var err error
	id, err = GenerateClientID()
	if err != nil {
		d.SrvLogger().Error("dcr id gen failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return "", "", "", false
	}
	secret, regToken, err = mintClientCredentials(d, public)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return "", "", "", false
	}
	return id, secret, regToken, true
}

// mintClientCredentials generates the client_secret (skipped for public
// clients per RFC 7591 §2 + RFC 6749 §2.3) and the RFC 7592 §3
// registration_access_token. Each generator failure keeps its own distinct
// log message; the returned error signals the caller to emit a 500. secret
// is "" for public clients.
func mintClientCredentials(d RegisterDeps, public bool) (secret, regToken string, err error) {
	if !public {
		secret, err = GenerateClientSecret()
		if err != nil {
			d.SrvLogger().Error("dcr secret gen failed", "error", err)
			return "", "", err
		}
	}
	regToken, err = GenerateClientSecret()
	if err != nil {
		d.SrvLogger().Error("dcr reg-token gen failed", "error", err)
		return "", "", err
	}
	return secret, regToken, nil
}

// buildRegisteredClient assembles the persisted core.Client for the
// /register success path from the validated request plus the freshly minted
// id/secret/registration_access_token.
// registrationTenant decides the new client's tenant. Under OPEN registration
// the body tenant_id is UNTRUSTED — an anonymous registrant must not self-assign
// into another tenant — so it is dropped (empty = default tenant). When the
// endpoint is gated by an InitialAccessToken the operator has vouched for the
// caller, so the requested tenant is honored. A 7592 PUT never changes the
// tenant (see buildUpdatedClient).
func registrationTenant(req *DCRRequest, policy *DCRPolicy) string {
	if policy != nil && policy.AllowOpenRegistration {
		return ""
	}
	return req.TenantID
}

// pkceMethodsForRegistration returns the AllowedPKCEMethods for a newly
// registered client. When PKCE is required (public client or explicitly
// requested), it defaults to S256 only — "plain" offers no protection against
// an observer of the authorization request (RFC 7636 §4.2) and is prohibited
// by OAuth 2.1. Operators can update AllowedPKCEMethods via the admin API.
func pkceMethodsForRegistration(requirePKCE bool) []string {
	if requirePKCE {
		return []string{PKCEMethodS256}
	}
	return nil
}

func buildRegisteredClient(req *DCRRequest, policy *DCRPolicy, id, secret, regToken string, public bool) *core.Client {
	tokenStrategy := req.TokenStrategy
	if tokenStrategy == "" {
		tokenStrategy = policy.DefaultTokenStrategy
	}
	return &core.Client{
		ID:                      id,
		Secret:                  secret,
		Name:                    req.ClientName,
		RedirectURIs:            append([]string(nil), req.RedirectURIs...),
		AllowedScopes:           SplitScope(req.Scope),
		AllowedAuthenticators:   append([]string(nil), req.AllowedAuthenticators...),
		TokenStrategy:           tokenStrategy,
		Active:                  policy.DefaultActive,
		TenantID:                registrationTenant(req, policy),
		RequirePKCE:             req.RequirePKCE || public, // public clients always PKCE
		AllowedPKCEMethods:      pkceMethodsForRegistration(req.RequirePKCE || public),
		AllowedResources:        append([]string(nil), req.AllowedResources...),
		PostLogoutRedirectURIs:  append([]string(nil), req.PostLogoutRedirectURIs...),
		RegistrationAccessToken: regToken,

		GrantTypes:                  append([]string(nil), req.GrantTypes...),
		IDTokenEncryptedResponseAlg:  req.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:  req.IDTokenEncryptedResponseEnc,
		UserinfoEncryptedResponseAlg: req.UserinfoEncryptedResponseAlg,
		UserinfoEncryptedResponseEnc: req.UserinfoEncryptedResponseEnc,
	}
}

// buildDCRResponse builds the RFC 7591 §3.2.1 successful-registration body,
// echoing the accepted metadata plus the issued credentials and the RFC 7592
// management URI. The secret + registration_access_token are revealed here
// at the only moment their plaintext is known.
func buildDCRResponse(req *DCRRequest, client *core.Client, ctx core.HandlerContext, secret, regToken string) DCRResponse {
	return DCRResponse{
		ClientID:                client.ID,
		ClientSecret:            secret,
		ClientIDIssuedAt:        time.Now().Unix(),
		ClientSecretExpiresAt:   0, // 0 = never expires per RFC 7591 §3.2.1
		RegistrationAccessToken: regToken,
		RegistrationClientURI:   middleware.BaseURL(ctx.Request()) + PathRegister + "/" + client.ID,
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
}

// rotateRAT implements the RFC 7592 §3.2 optional registration_access_token
// rotation on update. Default-off preserves the stable-token behavior;
// ratToStore is the value handed to the store (existing hash unchanged, or a
// fresh plaintext the store hashes at rest) and newRAT is the plaintext to
// reveal once in the response ("" => no rotation, field stays omitted). On a
// generator failure it keeps its own distinct log message and returns the
// error so the caller emits a 500.
func rotateRAT(d RegisterDeps, client *core.Client) (ratToStore, newRAT string, err error) {
	ratToStore = client.RegistrationAccessToken // existing hash, unchanged
	if !d.DCRPolicy().RotateRegistrationAccessToken {
		return ratToStore, "", nil
	}
	t, err := GenerateClientSecret()
	if err != nil {
		d.SrvLogger().Error("dcr reg-token rotation gen failed", "error", err)
		return "", "", err
	}
	return t, t, nil // plaintext; the store hashes it at rest on Update
}

// buildUpdatedClient assembles the core.Client for the RFC 7592 §2.2 update
// path. The client_secret stays unchanged (rotation is a separate admin RPC);
// ratToStore carries the preserved-or-rotated registration_access_token.
func buildUpdatedClient(req *DCRRequest, client *core.Client, ratToStore string) *core.Client {
	tokenStrategy := req.TokenStrategy
	if tokenStrategy == "" {
		tokenStrategy = client.TokenStrategy
	}
	return &core.Client{
		ID:                      client.ID,
		Secret:                  client.Secret, // unchanged
		RegistrationAccessToken: ratToStore,
		Active:                  client.Active,
		Name:                    req.ClientName,
		RedirectURIs:            append([]string(nil), req.RedirectURIs...),
		AllowedScopes:           SplitScope(req.Scope),
		AllowedAuthenticators:   append([]string(nil), req.AllowedAuthenticators...),
		TokenStrategy:           tokenStrategy,
		// Tenant is immutable across a 7592 update: the secret (hence the client
		// identity + tenant binding) is preserved, so a PUT MUST NOT let the
		// holder re-home the client into another tenant.
		TenantID: client.TenantID,
		// Derive public-ness from the STORED credential (the secret is preserved
		// above), NOT req.TokenEndpointAuthMethod — otherwise a PUT omitting or
		// changing that field could clear RequirePKCE on a still-public client,
		// reaching the public-client-without-PKCE state the create path forbids.
		RequirePKCE:        req.RequirePKCE || client.Secret == "",
		AllowedPKCEMethods: pkceMethodsForRegistration(req.RequirePKCE || client.Secret == ""),
		AllowedResources:   append([]string(nil), req.AllowedResources...),
		PostLogoutRedirectURIs:  append([]string(nil), req.PostLogoutRedirectURIs...),
		GrantTypes:              append([]string(nil), req.GrantTypes...),

		IDTokenEncryptedResponseAlg:  req.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:  req.IDTokenEncryptedResponseEnc,
		UserinfoEncryptedResponseAlg: req.UserinfoEncryptedResponseAlg,
		UserinfoEncryptedResponseEnc: req.UserinfoEncryptedResponseEnc,
	}
}
