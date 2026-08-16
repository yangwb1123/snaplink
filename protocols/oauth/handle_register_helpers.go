package oauth

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/middleware"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
	"github.com/yangwb1123/snaplink/shared/security/clientrotation"
)

const (
	dcrResponseTypesAttribute = "_snaplink_dcr_response_types"
	dcrContactsAttribute      = "_snaplink_dcr_contacts"
)

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func dcrJWKS(keys []core.JWK) *DCRJWKS {
	if len(keys) == 0 {
		return nil
	}
	return &DCRJWKS{Keys: append([]core.JWK(nil), keys...)}
}

func dcrRequestKeys(req *DCRRequest) []core.JWK {
	if req.JWKS == nil {
		return nil
	}
	return append([]core.JWK(nil), req.JWKS.Keys...)
}

func dcrAttributes(req *DCRRequest, existing map[string]string) map[string]string {
	out := make(map[string]string, len(existing)+2)
	for key, value := range existing {
		out[key] = value
	}
	for key, values := range map[string][]string{
		dcrResponseTypesAttribute: req.ResponseTypes,
		dcrContactsAttribute:      req.Contacts,
	} {
		data, _ := json.Marshal(values)
		out[key] = string(data)
	}
	return out
}

func dcrAttributeList(attributes map[string]string, key string) []string {
	out := []string{}
	if attributes != nil {
		_ = json.Unmarshal([]byte(attributes[key]), &out)
	}
	return out
}

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
	client := &core.Client{
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
		Attributes:              dcrAttributes(req, nil),
		JWKS:                    dcrRequestKeys(req),
		TLSClientAuthSubjectDN:  req.TLSClientAuthSubjectDN,
		TLSClientAuthSANDNS:     req.TLSClientAuthSANDNS,
		TLSClientAuthSANEmail:   req.TLSClientAuthSANEmail,
		TLSClientAuthSANURI:     req.TLSClientAuthSANURI,

		GrantTypes:                   append([]string(nil), req.GrantTypes...),
		TokenEndpointAuthMethod:      req.TokenEndpointAuthMethod,
		IDTokenEncryptedResponseAlg:  req.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:  req.IDTokenEncryptedResponseEnc,
		UserinfoEncryptedResponseAlg: req.UserinfoEncryptedResponseAlg,
		UserinfoEncryptedResponseEnc: req.UserinfoEncryptedResponseEnc,
		IDTokenSignedResponseAlg:     req.IDTokenSignedResponseAlg,
	}
	if !public {
		client.SecretExpiresAt = clientrotation.ExpiresAt(time.Now(), clientrotation.DefaultLifetime)
	}
	return client
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
		ClientSecretExpiresAt:   dcrClientSecretExpiry(client),
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
		TenantID:                client.TenantID,
		JWKS:                    dcrJWKS(client.JWKS),
		TLSClientAuthSubjectDN:  client.TLSClientAuthSubjectDN,
		TLSClientAuthSANDNS:     client.TLSClientAuthSANDNS,
		TLSClientAuthSANEmail:   client.TLSClientAuthSANEmail,
		TLSClientAuthSANURI:     client.TLSClientAuthSANURI,

		IDTokenEncryptedResponseAlg:  client.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:  client.IDTokenEncryptedResponseEnc,
		UserinfoEncryptedResponseAlg: client.UserinfoEncryptedResponseAlg,
		UserinfoEncryptedResponseEnc: client.UserinfoEncryptedResponseEnc,
		IDTokenSignedResponseAlg:     client.IDTokenSignedResponseAlg,
	}
}

func dcrClientSecretExpiry(client *core.Client) int64 {
	if client == nil || client.SecretExpiresAt.IsZero() {
		return 0
	}
	return client.SecretExpiresAt.Unix()
}

// rotateRAT implements the RFC 7592 §3.2 optional registration_access_token
// rotation on update. Default-off preserves the stable-token behavior;
// ratToStore is the value handed to the store (existing hash unchanged, or a
// fresh plaintext the store hashes at rest) and newRAT is the plaintext to
// reveal once in the response ("" => no rotation, field stays omitted). On a
// generator failure it keeps its own distinct log message and returns the
// error so the caller emits a 500.
type ratRotation struct {
	current, plaintext, previous string
	overlapUntil                 time.Time
}

func rotateRAT(d RegisterDeps, client *core.Client, bearer string) (ratRotation, error) {
	rotation := ratRotation{
		current: client.RegistrationAccessToken, previous: client.PreviousRegistrationAccessToken,
		overlapUntil: client.RegistrationAccessTokenOverlapUntil,
	}
	if !d.DCRPolicy().RotateRegistrationAccessToken {
		return rotation, nil
	}
	t, err := GenerateClientSecret()
	if err != nil {
		d.SrvLogger().Error("dcr reg-token rotation gen failed", "error", err)
		return ratRotation{}, err
	}
	if !validRegistrationTokenPrevious(client, bearer, time.Now()) {
		rotation.previous = client.RegistrationAccessToken
		overlap := d.DCRPolicy().RegistrationAccessTokenOverlap
		if overlap <= 0 {
			overlap = 5 * time.Minute
		}
		rotation.overlapUntil = time.Now().Add(overlap)
	}
	rotation.current, rotation.plaintext = t, t
	return rotation, nil
}

func validRegistrationTokenPrevious(client *core.Client, bearer string, now time.Time) bool {
	return !client.RegistrationAccessTokenOverlapUntil.IsZero() &&
		now.Before(client.RegistrationAccessTokenOverlapUntil) &&
		security.CompareClientSecret(client.PreviousRegistrationAccessToken, bearer)
}

// buildUpdatedClient assembles the core.Client for the RFC 7592 §2.2 update
// path. The client_secret stays unchanged (rotation is a separate admin RPC);
// ratToStore carries the preserved-or-rotated registration_access_token.
func buildUpdatedClient(req *DCRRequest, client *core.Client, rotation ratRotation) *core.Client {
	tokenStrategy := req.TokenStrategy
	if tokenStrategy == "" {
		tokenStrategy = client.TokenStrategy
	}
	// Preserve the stored TokenEndpointAuthMethod when the PUT omits it
	// (the typical case — the caller sends only the fields it wants to
	// update). When explicitly set, the update takes effect.
	tokenAuthMethod := req.TokenEndpointAuthMethod
	if tokenAuthMethod == "" {
		tokenAuthMethod = client.TokenEndpointAuthMethod
	}
	updated := *client
	updated.RegistrationAccessToken = rotation.current
	updated.PreviousRegistrationAccessToken = rotation.previous
	updated.RegistrationAccessTokenOverlapUntil = rotation.overlapUntil
	updated.Name = req.ClientName
	updated.RedirectURIs = append([]string(nil), req.RedirectURIs...)
	updated.AllowedScopes = SplitScope(req.Scope)
	updated.AllowedAuthenticators = append([]string(nil), req.AllowedAuthenticators...)
	updated.TokenStrategy = tokenStrategy
	updated.TokenEndpointAuthMethod = tokenAuthMethod
	updated.RequirePKCE = req.RequirePKCE || client.Secret == ""
	updated.AllowedPKCEMethods = pkceMethodsForRegistration(updated.RequirePKCE)
	updated.AllowedResources = append([]string(nil), req.AllowedResources...)
	updated.PostLogoutRedirectURIs = append([]string(nil), req.PostLogoutRedirectURIs...)
	updated.GrantTypes = append([]string(nil), req.GrantTypes...)
	updated.Attributes = dcrAttributes(req, client.Attributes)
	updated.JWKS = dcrRequestKeys(req)
	updated.TLSClientAuthSubjectDN = req.TLSClientAuthSubjectDN
	updated.TLSClientAuthSANDNS = req.TLSClientAuthSANDNS
	updated.TLSClientAuthSANEmail = req.TLSClientAuthSANEmail
	updated.TLSClientAuthSANURI = req.TLSClientAuthSANURI
	updated.IDTokenEncryptedResponseAlg = req.IDTokenEncryptedResponseAlg
	updated.IDTokenEncryptedResponseEnc = req.IDTokenEncryptedResponseEnc
	updated.UserinfoEncryptedResponseAlg = req.UserinfoEncryptedResponseAlg
	updated.UserinfoEncryptedResponseEnc = req.UserinfoEncryptedResponseEnc
	updated.IDTokenSignedResponseAlg = req.IDTokenSignedResponseAlg
	return &updated
}
