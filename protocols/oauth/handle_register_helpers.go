package oauth

import (
	"net/http"
	"time"

	"github.com/snaplink/sso/interfaces/middleware"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/core"
)

// recordRegistrationCreated writes the EventClientRegistered lifecycle event
// for a freshly minted confidential client on the /register path. The
// registration method (initial-access-token vs open) tells operators which
// gate produced it. Called ONLY after a successful store write — the
// failed-auth paths short-circuit earlier and emit nothing (anti-enumeration).
func recordRegistrationCreated(d RegisterDeps, ctx core.HandlerContext, policy *DCRPolicy, clientID string) {
	method := dcrMethodInitialAccessToken
	if policy.AllowOpenRegistration {
		method = dcrMethodOpen
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
	if bearer := BearerToken(ctx.Request()); bearer != policy.InitialAccessToken {
		d.SetBearerChallenge(ctx, d.ResolveIssuer(ctx), core.ErrInvalidToken, "Initial access token missing or invalid")
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidToken))
		return false
	}
	return true
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
		TenantID:                req.TenantID,
		RequirePKCE:             req.RequirePKCE || req.TokenEndpointAuthMethod == "none",
		AllowedResources:        append([]string(nil), req.AllowedResources...),
		PostLogoutRedirectURIs:  append([]string(nil), req.PostLogoutRedirectURIs...),

		IDTokenEncryptedResponseAlg:  req.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:  req.IDTokenEncryptedResponseEnc,
		UserinfoEncryptedResponseAlg: req.UserinfoEncryptedResponseAlg,
		UserinfoEncryptedResponseEnc: req.UserinfoEncryptedResponseEnc,
	}
}
