package oauth

import (
	"context"
	"net/http"
	"time"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/middleware"
	"github.com/snaplink/sso/spi"
	"github.com/snaplink/sso/tenant"
)

// CIBADeps is what HandleBackchannelAuth needs. *sso.Server satisfies
// it via accessor methods (accessors.go). oauth/ must not import oidc/,
// so hint resolution + the out-of-band delivery transport are exposed
// as Deps methods the Server implements over its own machinery.
type CIBADeps interface {
	ClientStoreAccessor() core.ClientStore
	CIBAStore() CIBAStore
	CIBARequestTTL() time.Duration
	CIBAPollInterval() time.Duration
	ResolveIssuer(ctx core.HandlerContext) string
	VerifyJWTClientAssertion(ctx context.Context, assertion, formClientID, asIssuer string) (string, error)
	SrvLogger() spi.Logger

	// ResolveCIBAHint maps the supplied hints (login_hint /
	// id_token_hint / login_hint_token) to a known user's subject id.
	// Returns ("", nil) when no hint resolves — the handler collapses
	// that to unknown_user_id per the anti-enumeration contract. The
	// provider name is the authenticator recorded for the eventual
	// token's AMR claim.
	ResolveCIBAHint(ctx context.Context, loginHint, idTokenHint, loginHintToken string) (subjectID, provider string, err error)

	// DeliverCIBAChallenge pushes the auth_req_id (and binding_message)
	// out of band via the wired PushTransport so the user can confirm
	// on their authentication device. Errors propagate as a 500 —
	// the request was persisted but the channel refused delivery, so
	// the operator must investigate (vs leaking a usable auth_req_id).
	DeliverCIBAChallenge(ctx context.Context, authReqID, subjectID, bindingMessage string) error

	// RecordCIBAAuthRequest emits the ciba_auth_request audit event.
	RecordCIBAAuthRequest(ctx core.HandlerContext, clientID, subjectID, authReqID string)
}

// HandleBackchannelAuth implements OpenID Connect CIBA Core 1.0 §7 in
// POLL delivery mode. The client (Consumption Device) POSTs the
// backchannel authentication request here; the AS resolves the hint to
// a user, persists a pending request, delivers the challenge out of
// band (reusing the Push MFA transport), and returns an auth_req_id +
// expires_in + interval the client polls /token with
// (grant_type=urn:openid:params:grant-type:ciba).
//
// Auth: HTTP Basic OR client_id+client_secret form body per RFC 6749
// §2.3.1 (Basic wins when both present — same precedence as /token and
// /par). private_key_jwt accepted via client_assertion.
//
// Poll mode only: at least one of login_hint / id_token_hint /
// login_hint_token MUST resolve to a known user; missing-hint and
// unresolvable-hint collapse to unknown_user_id (anti-enumeration).
func HandleBackchannelAuth(d CIBADeps, ctx core.HandlerContext) {
	middleware.TokenNoStoreHeaders(ctx)
	if d.CIBAStore() == nil {
		ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrCIBANotConfigured))
		return
	}
	if d.ClientStoreAccessor() == nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrServerMisconfigured))
		return
	}

	var req struct {
		ClientID                string   `json:"client_id"`
		ClientSecret            string   `json:"client_secret"`
		Scope                   string   `json:"scope"`
		LoginHint               string   `json:"login_hint"`                // OIDC Core §3.1.2.1
		IDTokenHint             string   `json:"id_token_hint"`             // OIDC Core §3.1.2.1
		LoginHintToken          string   `json:"login_hint_token"`          // CIBA Core §7.1
		BindingMessage          string   `json:"binding_message"`           // CIBA Core §7.1
		ACRValues               string   `json:"acr_values"`                // OIDC Core §3.1.2.1
		Nonce                   string   `json:"nonce"`                     // OIDC nonce
		Resource                []string `json:"resource"`                  // RFC 8707
		UserCode                string   `json:"user_code"`                 // CIBA Core §7.1 (user-code mode — unsupported)
		ClientNotificationToken string   `json:"client_notification_token"` // CIBA Core §7.1 (ping/push delivery)
		ClientAssertion         string   `json:"client_assertion"`          // RFC 7521 + 7523
		ClientAssertionType     string   `json:"client_assertion_type"`     // RFC 7521 + 7523
	}
	if err := BindParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if id, secret, ok := BasicClientCreds(ctx.Request()); ok {
		req.ClientID = id
		req.ClientSecret = secret
	}

	clientStore := d.ClientStoreAccessor()

	// RFC 7521/7523 — private_key_jwt client authentication, same as
	// /token and /par.
	if req.ClientAssertion != "" || req.ClientAssertionType != "" {
		if req.ClientAssertionType != ClientAssertionTypeJWTBearer {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
			return
		}
		assertedID, err := d.VerifyJWTClientAssertion(
			ctx.Request().Context(), req.ClientAssertion, req.ClientID, d.ResolveIssuer(ctx),
		)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidClient))
			return
		}
		req.ClientID = assertedID
	}

	if req.ClientID == "" {
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrMissingClientID))
		return
	}

	client, err := clientStore.Get(ctx.Request().Context(), req.ClientID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidClient))
		return
	}
	if !client.Active {
		ctx.JSON(http.StatusForbidden, core.ErrorBody(core.ErrInactiveClient))
		return
	}
	if !tenant.ClientOK(ctx, client) {
		ctx.JSON(http.StatusForbidden, core.ErrorBody(core.ErrTenantMismatch))
		return
	}
	if req.ClientAssertion == "" {
		if err := clientStore.ValidateSecret(ctx.Request().Context(), req.ClientID, req.ClientSecret); err != nil {
			ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidClientSecret))
			return
		}
	}
	if !client.AreResourcesAllowed(req.Resource) {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidTarget))
		return
	}

	// Poll mode only: at least one hint MUST be present. Empty-hint and
	// unresolvable-hint both collapse to unknown_user_id so a client
	// can't enumerate which usernames exist (anti-enumeration parity
	// with the rest of the surface).
	if req.LoginHint == "" && req.IDTokenHint == "" && req.LoginHintToken == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrUnknownUserID))
		return
	}
	subjectID, provider, err := d.ResolveCIBAHint(
		ctx.Request().Context(), req.LoginHint, req.IDTokenHint, req.LoginHintToken,
	)
	if err != nil || subjectID == "" {
		if err != nil {
			d.SrvLogger().Info("ciba hint resolution failed", "client_id", req.ClientID, "error", err)
		}
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrUnknownUserID))
		return
	}

	ttl := d.CIBARequestTTL()
	if ttl <= 0 {
		ttl = DefaultCIBARequestTTL
	}
	interval := d.CIBAPollInterval()
	if interval <= 0 {
		interval = DefaultCIBAPollInterval
	}
	now := time.Now()
	authReqID, err := d.CIBAStore().Issue(ctx.Request().Context(), &CIBARequest{
		ClientID:                req.ClientID,
		SubjectID:               subjectID,
		Provider:                provider,
		Scopes:                  SplitScope(req.Scope),
		ACRValues:               req.ACRValues,
		BindingMessage:          req.BindingMessage,
		Resources:               req.Resource,
		Nonce:                   req.Nonce,
		ClientNotificationToken: req.ClientNotificationToken,
		Status:                  CIBAPending,
		Interval:                interval,
		CreatedAt:               now,
		ExpiresAt:               now.Add(ttl),
	})
	if err != nil {
		d.SrvLogger().Error("ciba issue failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}

	// Deliver the challenge out of band. Failure → 500 + clean up the
	// dangling pending request (operators don't want auth_req_ids the
	// user can never confirm).
	if err := d.DeliverCIBAChallenge(ctx.Request().Context(), authReqID, subjectID, req.BindingMessage); err != nil {
		d.SrvLogger().Error("ciba challenge delivery failed", "error", err)
		_ = d.CIBAStore().Delete(ctx.Request().Context(), authReqID)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}

	d.RecordCIBAAuthRequest(ctx, req.ClientID, subjectID, authReqID)

	ctx.JSON(http.StatusOK, map[string]any{
		"auth_req_id": authReqID,
		"expires_in":  int(ttl.Seconds()),
		"interval":    int(interval.Seconds()),
	})
}
