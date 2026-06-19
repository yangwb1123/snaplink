package sso

import (
	"errors"
	"net/http"
	"strings"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/fapi"
	"github.com/snaplink/sso/oauth"
)

func (s *Server) handleToken(ctx HandlerContext) {
	// RFC 6749 §5.1: token responses (successful AND error) MUST
	// include Cache-Control: no-store + Pragma: no-cache so
	// intermediaries (browsers, HTTP caches, edge proxies) never
	// retain credentials. Set BEFORE writing the response body so
	// the header is on the wire regardless of which code path
	// returns. Same requirement applies to /token/introspect and
	// /token/revoke via tokenNoStoreHeaders below.
	tokenNoStoreHeaders(ctx)
	if err := s.requireDeps(DepTokenIssuer, DepClientStore); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	var req struct {
		GrantType    string   `json:"grant_type"`
		Code         string   `json:"code"`
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		RefreshToken string   `json:"refresh_token"`
		Scope        string   `json:"scope"`
		RedirectURI  string   `json:"redirect_uri"`
		CodeVerifier string   `json:"code_verifier"` // PKCE RFC 7636 §4.5
		DeviceCode   string   `json:"device_code"`   // RFC 8628 §3.4 device grant
		AuthReqID    string   `json:"auth_req_id"`   // OIDC CIBA Core §10.1 grant
		Resource     []string `json:"resource"`      // RFC 8707 resource indicators

		// RFC 8693 token-exchange parameters.
		SubjectToken       string   `json:"subject_token"`
		SubjectTokenType   string   `json:"subject_token_type"`
		ActorToken         string   `json:"actor_token"`
		ActorTokenType     string   `json:"actor_token_type"`
		Audience           []string `json:"audience"`
		RequestedTokenType string   `json:"requested_token_type"`
		// RFC 9470 step-up: caller may demand the exchanged token
		// carries an ACR at least as strong as one in this list.
		// Used when the subject_token was minted from a weak factor
		// (e.g. password only) but the downstream resource requires
		// MFA — caller passes acr_values="urn:mace:incommon:iap:silver"
		// and the dispatcher rejects with insufficient_user_authentication
		// when the inbound ACR doesn't satisfy.
		ACRValues string `json:"acr_values"`

		// RFC 7521 + 7523 JWT bearer client authentication.
		ClientAssertion     string `json:"client_assertion"`
		ClientAssertionType string `json:"client_assertion_type"`
	}
	if err := bindOAuthParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	// HTTP Basic auth takes precedence over body fields per RFC 6749 §2.3.1.
	var basicAuthUsed bool
	if id, secret, ok := basicClientCreds(ctx.Request()); ok {
		req.ClientID = id
		req.ClientSecret = secret
		basicAuthUsed = true
	}

	// RFC 7521 §4.2 + RFC 7523 §2.2 — JWT bearer client authentication.
	// When `client_assertion_type` is the jwt-bearer URN AND
	// `client_assertion` is supplied, the JWT replaces client_secret
	// as the proof of client identity. The JWT MUST be signed by a
	// key in Client.JWKS; iss / sub MUST equal the client_id; aud
	// MUST include the AS issuer or the token endpoint URL; exp
	// MUST be in the future. Replay defense (jti tracking) reuses
	// the security.JTIReplayStore wiring JAR already opts into.
	if req.ClientAssertion != "" || req.ClientAssertionType != "" {
		if req.ClientAssertionType != ClientAssertionTypeJWTBearer {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
			return
		}
		assertedID, err := verifyJWTClientAssertion(
			ctx.Request().Context(),
			req.ClientAssertion,
			req.ClientID,
			s.clientStore,
			s.resolveIssuer(ctx),
			s.jtiReplayStore,
			s.jtiReplayFailClosed,
		)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClient))
			return
		}
		req.ClientID = assertedID
	}

	client, err := s.clientStore.Get(ctx.Request().Context(), req.ClientID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClient))
		return
	}
	if !clientTenantOK(ctx, client) {
		ctx.JSON(http.StatusForbidden, errorBody(ErrTenantMismatch))
		return
	}
	// Skip the client_secret check when the caller authenticated
	// via JWT assertion — Client.JWKS verification stands in for
	// the secret. RFC 7521 §4.2 prohibits requiring BOTH proofs.
	if req.ClientAssertion == "" {
		if err := s.clientStore.ValidateSecret(ctx.Request().Context(), req.ClientID, req.ClientSecret); err != nil {
			// RFC 6749 §5.2: all client-authentication failures return
			// invalid_client. Collapsing wrong-secret into the same code as
			// unknown-client (above) is also oracle-safe — a distinct
			// invalid_client_secret would let an attacker enumerate valid
			// client_ids by the error code alone.
			ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClient))
			return
		}
	}
	// RFC 8707 §2: each requested `resource` MUST be allowlisted on
	// the client. Empty allowlist disables enforcement (legacy compat).
	if !client.AreResourcesAllowed(req.Resource) {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidTarget))
		return
	}

	// Data-residency WRITE-gate for token issuance. The login flow already
	// gates its mints; this closes the grant-side hole so a refresh rotation,
	// token-exchange, CIBA, device, or code-exchange mint can't produce fresh
	// credentials for a region-constrained tenant from a disallowed serving
	// region. Checked once here, before the grant switch, so it applies to
	// every minting grant uniformly. Byte-identical when residency is unwired.
	if s.residencyGateTokenGrant(ctx, client) {
		return
	}

	// RFC 9449 — DPoP. When the request carries a `DPoP` header,
	// validate the proof and stash the resulting JKT so the grant
	// branches below can bind the issued access token to the key.
	// Absence of the header keeps the legacy bearer-token path —
	// DPoP is opt-in per request, never required by this server.
	var dpopJKT string
	if proof := ctx.Request().Header.Get(HeaderDPoP); proof != "" {
		binding, err := verifyDPoPProof(
			ctx.Request().Context(),
			proof,
			ctx.Request().Method,
			requestURLForDPoP(ctx.Request()),
			s.jtiReplayStore,
			s.jtiReplayFailClosed,
			s.dpopNonceProvider,
			s.resolvedDPoPProofMaxAge(),
			s.resolvedDPoPProofClockSkew(),
		)
		if err != nil {
			// RFC 9449 §8 — nonce required: stamp a fresh nonce on
			// the response and respond with use_dpop_nonce instead
			// of invalid_dpop_proof so clients can retry. AS-side
			// uses HTTP 400 (vs 401 for RS-side).
			if errors.Is(err, ErrDPoPNonceRequired) {
				s.stampDPoPNonce(ctx)
				s.logger.Info("dpop nonce challenge", "method", ctx.Request().Method)
				ctx.JSON(http.StatusBadRequest, errorBody(ErrUseDPoPNonce))
				return
			}
			s.logger.Error("dpop proof failed", "error", err)
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidDPoPProof))
			return
		}
		dpopJKT = binding.JKT
	}

	// RFC 8705 §3 — mTLS certificate-bound access tokens. When a
	// client cert extractor is wired AND the inbound request
	// carries a client cert, stamp the cert's SHA-256 thumbprint
	// into the token's cnf.x5t#S256 claim. Mutually exclusive
	// with DPoP — first-set wins (caller MUST NOT supply both,
	// the configuration is per-token).
	var mtlsX5T string
	if s.clientCertExtractor != nil {
		if cert, ok := s.clientCertExtractor.ExtractClientCert(ctx.Request()); ok && cert != nil {
			mtlsX5T = certificateThumbprintS256(cert)
		}
	}

	// FAPI 2.0 Security Profile — issued access tokens MUST be
	// sender-constrained via DPoP or mTLS. Checked once here, before
	// the grant switch, so it applies uniformly to every grant that
	// mints an access token. Inspection mode audits and proceeds;
	// enforce mode rejects with invalid_request (a bearer-only token
	// request is the violation, not a credential failure — no oracle
	// concern). The rule id lands in the audit event; the wire stays
	// the standard error code.
	if s.fapiValidator.Active() {
		// Classify the client-authentication method used on this token
		// request so the FAPI client-auth rule can reject shared-secret
		// auth. private_key_jwt (assertion) and mTLS (client cert) are
		// the only FAPI-permitted methods; Basic / body secret map to
		// the prohibited shared-secret methods.
		clientAuthMethod := fapi.ClientAuthNone
		switch {
		case req.ClientAssertion != "":
			clientAuthMethod = fapi.ClientAuthPrivateKeyJWT
		case mtlsX5T != "":
			clientAuthMethod = fapi.ClientAuthTLS
		case basicAuthUsed:
			clientAuthMethod = fapi.ClientAuthSecretBasic
		case req.ClientSecret != "":
			clientAuthMethod = fapi.ClientAuthSecretPost
		}
		if vs := s.fapiValidator.CheckToken(fapi.TokenContext{
			ClientID:          req.ClientID,
			GrantType:         req.GrantType,
			SenderConstrained: dpopJKT != "" || mtlsX5T != "",
			ClientAuthMethod:  clientAuthMethod,
		}); len(vs) > 0 {
			mode := s.fapiValidator.Mode().String()
			for _, v := range vs {
				audit.RecordFAPIViolation(s.auditor, ctx, v.ClientID, v.RuleID, v.Detail, mode)
				if s.metrics != nil {
					s.metrics.FAPIViolationsTotal.WithLabelValues(v.RuleID, mode).Inc()
				}
			}
			if s.fapiValidator.Enforcing() {
				ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
				return
			}
		}
	}

	var scopes []string
	if req.Scope != "" {
		scopes = strings.Split(req.Scope, " ")
	}

	switch req.GrantType {
	case GrantAuthorizationCode:
		s.handleAuthCodeTokenGrant(ctx, client, req, scopes, dpopJKT, mtlsX5T)
	case GrantRefreshToken:
		s.handleRefreshTokenGrant(ctx, client, req.RefreshToken, req.Scope, dpopJKT, mtlsX5T)
	case GrantDeviceCode:
		s.handleDeviceTokenGrant(ctx, client, req.DeviceCode)
	case GrantCIBA:
		s.handleCIBATokenGrant(ctx, client, req.AuthReqID, dpopJKT, mtlsX5T)
	case GrantTokenExchange:
		s.handleTokenExchangeGrant(ctx, client, tokenExchangeRequest{
			SubjectToken:       req.SubjectToken,
			SubjectTokenType:   req.SubjectTokenType,
			ActorToken:         req.ActorToken,
			ActorTokenType:     req.ActorTokenType,
			Resource:           req.Resource,
			Audience:           req.Audience,
			Scope:              req.Scope,
			RequestedTokenType: req.RequestedTokenType,
			ACRValues:          req.ACRValues,
		})
	case GrantClientCredentials:
		strategy, ti, err := s.issuerForClient(client)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrNoTokenStrategy))
			return
		}
		// Scope authorization (RFC 6749 §3.3). The client is already
		// authenticated above (HTTP Basic > body creds), so this gate is
		// not a pre-auth probe. Reject an out-of-allowlist scope with a
		// 400 invalid_scope (/token shape, not the authz body); default
		// an empty request to the client's AllowedScopes so the token
		// carries its entitled scope. Empty allowlist = unrestricted
		// (byte-identical to the old pass-through).
		grantCCScopes, ccScopeErr := oauth.GrantedScopes(scopes, client)
		if ccScopeErr != nil {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidScope))
			return
		}
		// client_credentials: subject IS the client, so ClientID =
		// Sub. No end-user auth event, hence no AuthTime/AMR.
		token, err := ti.Issue(ctx.Request().Context(), &Subject{
			ID: client.ID, Resources: req.Resource, ClientID: client.ID,
			TTL:                 client.AccessTokenTTL,
			ConfirmationJKT:     dpopJKT,
			ConfirmationX5TS256: mtlsX5T,
		}, grantCCScopes)
		if err != nil {
			s.logErrorCtx(ctx, "token issuance failed", "strategy", strategy, "error", err)
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
			return
		}
		s.recordTokenIssued(ctx, client.ID, strategy, client.ID)
		ctx.JSON(http.StatusOK, map[string]any{
			KeyAccessToken:   token.AccessToken,
			KeyTokenType:     dpopTokenTypeOr(token.TokenType, dpopJKT),
			KeyExpiresIn:     token.ExpiresIn,
			KeyScope:         token.Scope,
			KeyTokenStrategy: strategy,
		})
	default:
		ctx.JSON(http.StatusBadRequest, map[string]any{
			KeyError:           ErrUnsupportedGrantType,
			KeySupportedGrants: SupportedGrants,
		})
	}
}
