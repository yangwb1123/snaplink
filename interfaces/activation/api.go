// Package activationhttp exposes the optional public activation and
// authenticated account-context routes used by hosted-login SDKs.
package activationhttp

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/activation"
	"github.com/yangwb1123/snaplink/shared/core"
)

type BearerVerifier interface {
	MeClaimsOrChallenge(core.HandlerContext) (*core.TokenClaims, bool)
}

type API struct {
	store    activation.Store
	verifier BearerVerifier
}

type prepareRequest struct {
	ClientID       string `json:"client_id"`
	ProductID      string `json:"product_id"`
	LicenseKey     string `json:"license_key"`
	InvitationCode string `json:"invitation_code"`
	TenantHint     string `json:"tenant_hint"`
	Locale         string `json:"locale"`
	AppVersion     string `json:"app_version"`
}

type claimRequest struct {
	ActivationTicket string `json:"activation_ticket"`
	ProductID        string `json:"product_id"`
}

type preparationResponse struct {
	ActivationTicket string `json:"activation_ticket"`
	ProductID        string `json:"product_id"`
	ExpiresIn        int64  `json:"expires_in"`
}

type contextResponse struct {
	Context *activation.AccountContext `json:"context"`
}

func New(store activation.Store, verifier BearerVerifier) (*API, error) {
	if store == nil || verifier == nil {
		return nil, errors.New("activation http: store and bearer verifier are required")
	}
	return &API{store: store, verifier: verifier}, nil
}

func Mount(router core.Router, store activation.Store, verifier BearerVerifier) error {
	if router == nil {
		return errors.New("activation http: router is required")
	}
	api, err := New(store, verifier)
	if err != nil {
		return err
	}
	return api.RegisterRoutes(router)
}

func (a *API) RegisterRoutes(router core.Router) error {
	if router == nil {
		return errors.New("activation http: router is required")
	}
	router.POST(PathPrepare, a.handlePrepare)
	router.POST(PathClaim, a.handleClaim)
	router.GET(PathContext, a.handleContext)
	return nil
}

func (a *API) handlePrepare(ctx core.HandlerContext) {
	noStore(ctx)
	var request prepareRequest
	if err := ctx.Bind(&request); err != nil {
		writeError(ctx, http.StatusBadRequest, core.ErrInvalidRequest)
		return
	}
	prepared, err := a.store.Prepare(ctx.Request().Context(), activation.PrepareInput{
		ClientID: request.ClientID, ProductID: request.ProductID,
		LicenseKey: request.LicenseKey, InvitationCode: request.InvitationCode,
		TenantHint: request.TenantHint,
	})
	if err != nil {
		writeActivationError(ctx, err, false)
		return
	}
	ctx.JSON(http.StatusOK, preparationResponse{
		ActivationTicket: prepared.Ticket, ProductID: prepared.ProductID,
		ExpiresIn: expiresIn(prepared.ExpiresAt),
	})
}

func (a *API) handleClaim(ctx core.HandlerContext) {
	noStore(ctx)
	claims, ok := a.verifier.MeClaimsOrChallenge(ctx)
	if !ok {
		return
	}
	var request claimRequest
	if err := ctx.Bind(&request); err != nil {
		writeError(ctx, http.StatusBadRequest, core.ErrInvalidRequest)
		return
	}
	result, err := a.store.Claim(ctx.Request().Context(), activation.ClaimInput{
		Ticket: request.ActivationTicket, ClientID: claims.ClientID,
		ProductID: request.ProductID, Subject: claims.Subject,
	})
	if err != nil {
		writeActivationError(ctx, err, false)
		return
	}
	ctx.JSON(http.StatusOK, contextResponse{Context: result})
}

func (a *API) handleContext(ctx core.HandlerContext) {
	noStore(ctx)
	claims, ok := a.verifier.MeClaimsOrChallenge(ctx)
	if !ok {
		return
	}
	productID := strings.TrimSpace(ctx.Query("product_id"))
	result, err := a.store.Current(ctx.Request().Context(), activation.CurrentInput{
		ClientID: claims.ClientID, ProductID: productID, Subject: claims.Subject,
	})
	if err != nil {
		writeActivationError(ctx, err, true)
		return
	}
	ctx.JSON(http.StatusOK, contextResponse{Context: result})
}

func writeActivationError(ctx core.HandlerContext, err error, notFound bool) {
	if errors.Is(err, activation.ErrInvalidActivation) {
		if notFound {
			writeError(ctx, http.StatusNotFound, ErrorActivationNotFound)
			return
		}
		writeError(ctx, http.StatusBadRequest, ErrorActivationInvalid)
		return
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		writeError(ctx, http.StatusServiceUnavailable, ErrorActivationUnavailable)
		return
	}
	writeError(ctx, http.StatusServiceUnavailable, ErrorActivationUnavailable)
}

func writeError(ctx core.HandlerContext, status int, code string) {
	ctx.JSON(status, core.ErrorBody(code))
}

func noStore(ctx core.HandlerContext) {
	header := ctx.ResponseWriter().Header()
	header.Set(HeaderCacheControl, "no-store")
	header.Set(HeaderPragma, "no-cache")
}

func expiresIn(deadline time.Time) int64 {
	seconds := int64(time.Until(deadline) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}
