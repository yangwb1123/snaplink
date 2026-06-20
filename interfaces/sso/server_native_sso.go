package sso

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/snaplink/sso/internal/handler"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/protocols/oidc"
)

// issueDeviceSecret mints a fresh Native SSO device_secret, stores its binding,
// and returns the plaintext (revealed once in the token response). 256 bits of
// entropy, base64url. Used by both the direct-login and token-exchange paths.
func (s *Server) issueDeviceSecret(ctx context.Context, subject, sid, clientID string) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(buf)
	ttl := s.deviceSecretTTL
	if ttl <= 0 {
		ttl = DefaultDeviceSecretTTL
	}
	if err := s.deviceSecretStore.Issue(ctx, &DeviceSecret{
		Secret:    secret,
		Subject:   subject,
		SID:       sid,
		ClientID:  clientID,
		ExpiresAt: time.Now().Add(ttl),
	}); err != nil {
		return "", err
	}
	return secret, nil
}

// handleDeviceSecretExchange implements the OpenID Connect Native SSO 1.0 §3.2
// token exchange: a second native app presents the first app's id_token
// (subject_token, type=id_token) plus the device_secret (actor_token,
// type=device-secret) to obtain its OWN tokens without re-authenticating the
// user. It is self-contained (the id_token carries no scopes, so generic
// subject-subset narrowing does not apply) and writes its own response. Every
// validation failure collapses to invalid_grant (oracle-safe); the precise
// cause goes only to the audit trail.
//
// idTokenClaims is the validated subject_token; rawIDToken is its compact JWS
// (needed to read the alg header + ds_hash claim, which TokenClaims omits).
func (s *Server) handleDeviceSecretExchange(ctx HandlerContext, idTokenClaims *TokenClaims, rawIDToken, deviceSecret string, client *Client, req handler.TokenExchangeRequest) {
	fail := func(reason string) {
		s.recordNativeSSOFailure(ctx, client.ID, idTokenClaims.Subject, reason)
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
	}

	// The subject_token MUST be an id_token for this path.
	if req.SubjectTokenType != TokenTypeIDToken {
		fail("subject_token_type not id_token")
		return
	}
	alg, err := idTokenAlg(rawIDToken)
	if err != nil {
		fail("id_token header unreadable")
		return
	}
	storedDsHash, err := idTokenDsHash(rawIDToken)
	if err != nil || storedDsHash == "" {
		fail("id_token missing ds_hash")
		return
	}
	// Bind the secret to the id_token: ds_hash MUST equal the left-half hash of
	// the presented device_secret (constant-time).
	expected := dsHash(alg, deviceSecret)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(storedDsHash)) != 1 {
		fail("ds_hash mismatch")
		return
	}
	// Validate + consume the secret (single-use). Missing/expired/consumed all
	// collapse to invalid_grant.
	binding, err := s.deviceSecretStore.Consume(ctx.Request().Context(), deviceSecret)
	if err != nil {
		fail("device_secret not found")
		return
	}
	// The secret must belong to the same subject the id_token asserts, and —
	// when both sides carry a session id — the same session.
	if binding.Subject != idTokenClaims.Subject {
		fail("subject mismatch")
		return
	}
	if binding.SID != "" && idTokenClaims.SID != "" && binding.SID != idTokenClaims.SID {
		fail("session mismatch")
		return
	}

	// Scopes: the requesting app's requested scope bounded by ITS allowlist
	// (device_sso + openid bypass it). An id_token has no scopes, so there is
	// no subject-subset to narrow against.
	var requested []string
	if req.Scope != "" {
		requested = strings.Fields(req.Scope)
	}
	scopes, scopeErr := oauth.GrantedScopes(requested, client)
	if scopeErr != nil {
		fail("scope not allowed")
		return
	}
	resources := mergeTargets(req.Resource, req.Audience)
	if !client.AreResourcesAllowed(resources) {
		fail("resource not allowed")
		return
	}

	strategy, ti, err := s.issuerForClient(client)
	if err != nil {
		// Misconfiguration, not a credential failure.
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrNoTokenStrategy))
		return
	}
	localSub, _ := s.resolveLocalSubject(ctx.Request().Context(), idTokenClaims.Subject)
	issuedSub := s.applyPairwiseSubject(ctx.Request().Context(), client, localSub)

	token, err := ti.Issue(ctx.Request().Context(), &Subject{
		ID:        issuedSub,
		ClientID:  client.ID,
		AuthTime:  idTokenClaims.AuthTime,
		AMR:       idTokenClaims.AMR,
		ACR:       idTokenClaims.ACR,
		SID:       idTokenClaims.SID,
		Resources: resources,
		TTL:       client.AccessTokenTTL,
	}, scopes)
	if err != nil {
		s.logErrorCtx(ctx, "native sso token issuance failed", "strategy", strategy, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}

	// Mint a fresh device_secret for the requesting app (rotation — the old one
	// was consumed) when device_sso is in the granted scopes.
	var newDeviceSecret string
	if slices.Contains(scopes, ScopeDeviceSSO) {
		if ds, dsErr := s.issueDeviceSecret(ctx.Request().Context(), issuedSub, idTokenClaims.SID, client.ID); dsErr != nil {
			s.logger.Error("native sso device secret reissue failed", "error", dsErr, "client", client.ID)
		} else {
			newDeviceSecret = ds
		}
	}

	resp := map[string]any{
		KeyAccessToken:     token.AccessToken,
		KeyIssuedTokenType: TokenTypeAccessToken,
		KeyTokenType:       token.TokenType,
		KeyExpiresIn:       token.ExpiresIn,
		KeyScope:           token.Scope,
		KeyTokenStrategy:   strategy,
		KeyIss:             s.resolveIssuer(ctx),
	}
	if slices.Contains(scopes, ScopeOpenID) {
		if idIssuer, emit, idErr := s.idTokenIssuerForClient(client); idErr == nil && emit {
			idToken, iErr := idIssuer.IssueIDToken(ctx.Request().Context(), &oidc.IDTokenRequest{
				Subject:      issuedSub,
				Audience:     client.ID,
				AuthTime:     idTokenClaims.AuthTime,
				AMR:          idTokenClaims.AMR,
				ACR:          idTokenClaims.ACR,
				SID:          idTokenClaims.SID,
				AccessToken:  token.AccessToken,
				DeviceSecret: newDeviceSecret,
			})
			if iErr == nil {
				if enc, ok := s.maybeEncryptIDToken(ctx.Request().Context(), client, idToken); ok {
					resp[KeyIDToken] = enc
				}
			}
		}
	}
	if newDeviceSecret != "" {
		resp[KeyDeviceSecret] = newDeviceSecret
	}
	s.recordTokenIssued(ctx, client.ID, strategy, issuedSub)
	s.recordNativeSSOExchange(ctx, client.ID, issuedSub, binding.ClientID)
	ctx.JSON(http.StatusOK, resp)
}

// dsHash computes the Native SSO ds_hash for a device_secret: the base64url
// left-half of the secret's hash, the hash chosen by the id_token's signing
// alg (EdDSA→SHA-512, everything else→SHA-256). Mirrors the issuer's at_hash
// construction so an RP / this AS recompute the same value.
func dsHash(alg, deviceSecret string) string {
	if deviceSecret == "" {
		return ""
	}
	var digest []byte
	switch alg {
	case "EdDSA":
		sum := sha512.Sum512([]byte(deviceSecret))
		digest = sum[:]
	default:
		sum := sha256.Sum256([]byte(deviceSecret))
		digest = sum[:]
	}
	return base64.RawURLEncoding.EncodeToString(digest[:len(digest)/2])
}

// idTokenAlg reads the `alg` from a compact JWS header (segment 0).
func idTokenAlg(compact string) (string, error) {
	seg, err := jwsSegment(compact, 0)
	if err != nil {
		return "", err
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(seg, &h); err != nil {
		return "", err
	}
	return h.Alg, nil
}

// idTokenDsHash reads the `ds_hash` claim from a compact JWS payload (segment 1).
func idTokenDsHash(compact string) (string, error) {
	seg, err := jwsSegment(compact, 1)
	if err != nil {
		return "", err
	}
	var p struct {
		DsHash string `json:"ds_hash"`
	}
	if err := json.Unmarshal(seg, &p); err != nil {
		return "", err
	}
	return p.DsHash, nil
}

// jwsSegment base64url-decodes the nth dot-separated segment of a compact JWS.
func jwsSegment(compact string, n int) ([]byte, error) {
	parts := strings.Split(compact, ".")
	if len(parts) < 3 || n >= len(parts) {
		return nil, errors.New("sso: not a compact JWS")
	}
	return base64.RawURLEncoding.DecodeString(parts[n])
}

// recordNativeSSOExchange / recordNativeSSOFailure emit the audit trail. The
// failure reason is recorded ONLY here (never on the wire — the response is a
// uniform invalid_grant).
func (s *Server) recordNativeSSOExchange(ctx HandlerContext, clientID, subject, originalClient string) {
	if s.auditor == nil {
		return
	}
	e := audit.EventFromRequest(ctx)
	e.Type = audit.EventNativeSSOExchange
	e.Outcome = audit.OutcomeSuccess
	e.ClientID = clientID
	e.ActorID = subject
	audit.SetMeta(e, "original_client", originalClient)
	s.auditor.Record(ctx.Request().Context(), e)
}

func (s *Server) recordNativeSSOFailure(ctx HandlerContext, clientID, subject, reason string) {
	if s.auditor == nil {
		return
	}
	e := audit.EventFromRequest(ctx)
	e.Type = audit.EventNativeSSOExchangeFailure
	e.Outcome = audit.OutcomeFailure
	e.ClientID = clientID
	e.ActorID = subject
	e.Reason = reason
	s.auditor.Record(ctx.Request().Context(), e)
}
