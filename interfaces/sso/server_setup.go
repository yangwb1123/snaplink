package sso

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/internal/handler/tokengrant"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

const (
	PathSetupStatus = "/api/v1/setup/status"
	PathSetup       = "/api/v1/setup"
)

const (
	setupAdminRoleCode         = "sso-admin"
	setupAdminClientID         = ""
	setupMinPasswordLen        = 8
	errSetupAlreadyInitialized = "already_initialized"
	errSetupDisabled           = "not_found"
)

type setupApplicationRequest struct {
	Name                 string   `json:"name"`
	RedirectURIs         []string `json:"redirect_uris"`
	RecoveryClientID     string   `json:"recovery_client_id,omitempty"`
	RecoveryClientSecret string   `json:"recovery_client_secret,omitempty"`
}

type setupRequest struct {
	Admin struct {
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"admin"`
	Application *setupApplicationRequest `json:"application"`
}

func (s *Server) setupWizardOn() bool { return s.setupWizardEnabled }

func (s *Server) setupInitialized(ctx context.Context) bool {
	if s.permissions != nil {
		if assignments, err := s.permissions.ListAssignments(ctx, setupAdminClientID); err == nil {
			for _, assignment := range assignments {
				if slices.Contains(assignment.Roles, setupAdminRoleCode) {
					return true
				}
			}
		}
	}
	if s.userProvider != nil {
		users, err := s.userProvider.List(ctx)
		return err == nil && len(users) > 0
	}
	return false
}

func (s *Server) handleSetupStatus(ctx HandlerContext) {
	if !s.setupWizardOn() {
		ctx.JSON(http.StatusNotFound, map[string]string{core.KeyError: errSetupDisabled})
		return
	}
	done := s.setupInitialized(ctx.Request().Context())
	ctx.JSON(http.StatusOK, map[string]any{"initialized": done, "setup_required": !done})
}

func (s *Server) handleSetup(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	if !s.setupWizardOn() {
		ctx.JSON(http.StatusNotFound, map[string]string{core.KeyError: errSetupDisabled})
		return
	}
	req, ok := bindSetupRequest(ctx)
	if !ok {
		return
	}
	reqCtx := ctx.Request().Context()
	if s.setupInitialized(reqCtx) {
		s.handleSetupRecovery(ctx, req)
		return
	}
	if err := s.provisionFirstAdmin(reqCtx, req.Admin.Username, req.Admin.Password); err != nil {
		s.logger.Error("setup: provision first admin failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrInternal))
		return
	}
	s.finishInitialSetup(ctx, req)
}

func bindSetupRequest(ctx HandlerContext) (setupRequest, bool) {
	var req setupRequest
	if err := ctx.Bind(&req); err != nil ||
		req.Admin.Username == "" || len(req.Admin.Password) < setupMinPasswordLen {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidRequest))
		return setupRequest{}, false
	}
	return req, true
}

func (s *Server) finishInitialSetup(ctx HandlerContext, req setupRequest) {
	created := map[string]any{"admin": req.Admin.Username}
	app := req.Application
	if app == nil || app.Name == "" {
		s.writeSetupSuccess(ctx, created, false)
		return
	}
	id, secret, err := s.provisionFirstClient(ctx.Request().Context(), app)
	if err != nil {
		s.logger.Error("setup: provision first application failed", "error", err)
		s.writeSetupPartial(ctx, req.Admin.Username, app, id, secret)
		return
	}
	created["application"] = setupClientCredentials(id, secret)
	s.writeSetupSuccess(ctx, created, false)
}

func (s *Server) handleSetupRecovery(ctx HandlerContext, req setupRequest) {
	app := req.Application
	reqCtx := ctx.Request().Context()
	if app == nil || app.RecoveryClientID == "" || app.RecoveryClientSecret == "" ||
		!s.setupRecoveryAuthorized(reqCtx, req.Admin.Username, req.Admin.Password) {
		ctx.JSON(http.StatusConflict, map[string]string{core.KeyError: errSetupAlreadyInitialized})
		return
	}
	id, secret, err := s.provisionFirstClientWithCredentials(reqCtx, app)
	if err != nil {
		s.logger.Error("setup: recover first application failed", "error", err)
		s.writeSetupPartial(ctx, req.Admin.Username, app, id, secret)
		return
	}
	created := map[string]any{
		"admin":       req.Admin.Username,
		"application": setupClientCredentials(id, secret),
	}
	s.writeSetupSuccess(ctx, created, true)
}

func (s *Server) setupRecoveryAuthorized(ctx context.Context, username, password string) bool {
	if s.passwordCredentialStore == nil || s.permissions == nil {
		return false
	}
	if err := s.passwordCredentialStore.VerifyPassword(ctx, username, password); err != nil {
		return false
	}
	assignments, err := s.permissions.ListAssignments(ctx, setupAdminClientID)
	if err != nil {
		return false
	}
	for _, assignment := range assignments {
		if assignment.UserID == username && slices.Contains(assignment.Roles, setupAdminRoleCode) {
			return true
		}
	}
	return false
}

func (s *Server) writeSetupSuccess(ctx HandlerContext, created map[string]any, recovered bool) {
	s.logger.Info("first-run setup completed", "admin", created["admin"], "recovered", recovered)
	ctx.JSON(http.StatusOK, map[string]any{
		"ok": true, "status": "complete", "created": created, "recovered": recovered,
	})
}

func (s *Server) writeSetupPartial(
	ctx HandlerContext, admin string, app *setupApplicationRequest, id, secret string,
) {
	recoveryApp := *app
	recoveryApp.RecoveryClientID = id
	recoveryApp.RecoveryClientSecret = secret
	ctx.JSON(http.StatusMultiStatus, map[string]any{
		"ok": false, "status": "partial_success",
		"created": map[string]any{"admin": admin},
		"failed": []map[string]any{{
			"resource": "application", "code": "provision_failed", "retryable": true,
		}},
		"recovery": map[string]any{
			"action": "retry_setup_application", "method": http.MethodPost,
			"path": PathSetup, "application": recoveryApp,
		},
	})
}

func setupClientCredentials(id, secret string) map[string]string {
	return map[string]string{"client_id": id, "client_secret": secret}
}

func (s *Server) provisionFirstAdmin(ctx context.Context, username, password string) error {
	if s.permissions == nil || s.userProvider == nil || s.passwordCredentialStore == nil {
		return errors.New("setup: user, permissions and password stores must all be wired")
	}
	if err := s.permissions.AddRole(ctx, setupAdminClientID, permissions.Role{
		Code: setupAdminRoleCode, Name: "SSO Administrator",
		Description: "Full admin:* scope across the control plane.", Permissions: []string{AdminScope},
	}); err != nil && !errors.Is(err, permissions.ErrRoleExists) {
		return err
	}
	if err := s.userProvider.CreateOrUpdate(ctx, &core.User{
		ID: username, ExternalID: username, Provider: "password",
	}); err != nil {
		return err
	}
	if err := s.passwordCredentialStore.SetPassword(ctx, username, password); err != nil {
		return err
	}
	return s.permissions.AssignRoles(ctx, username, setupAdminClientID, []string{setupAdminRoleCode})
}

func (s *Server) provisionFirstClient(
	ctx context.Context, app *setupApplicationRequest,
) (string, string, error) {
	id, err := generateAuthCodeBytes()
	if err != nil {
		return "", "", err
	}
	secret, err := generateAuthCodeBytes()
	if err != nil {
		return id, "", err
	}
	recovery := *app
	recovery.RecoveryClientID = id
	recovery.RecoveryClientSecret = secret
	return s.provisionFirstClientWithCredentials(ctx, &recovery)
}

func (s *Server) provisionFirstClientWithCredentials(
	ctx context.Context, app *setupApplicationRequest,
) (string, string, error) {
	id, secret := app.RecoveryClientID, app.RecoveryClientSecret
	if s.clientStore == nil {
		return id, secret, errors.New("setup: client store not wired")
	}
	if _, err := s.clientStore.Get(ctx, id); err == nil {
		return id, secret, s.clientStore.ValidateSecret(ctx, id, secret)
	} else if !errors.Is(err, core.ErrNoSuchClient) {
		return id, secret, err
	}
	client := setupClient(app, id, secret)
	if err := s.clientStore.Add(ctx, client); err != nil {
		return id, secret, err
	}
	return id, secret, nil
}

func setupClient(app *setupApplicationRequest, id, secret string) *core.Client {
	return &core.Client{
		ID: id, Secret: secret, Name: app.Name, RedirectURIs: app.RedirectURIs,
		AllowedScopes:         []string{"openid", "profile", "email"},
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         TokenStrategyJWT, Active: true,
	}
}

// SAMLAssertionValidator validates an RFC 7522 SAML 2.0 bearer assertion.
type SAMLAssertionValidator = tokengrant.SAMLAssertionValidator

// WithSAML2BearerGrant enables the RFC 7522 SAML bearer assertion grant.
func WithSAML2BearerGrant(validator SAMLAssertionValidator) Option {
	return func(s *Server) {
		if validator == nil {
			return
		}
		s.saml2BearerValidator = validator
		if s.customGrantHandlers == nil {
			s.customGrantHandlers = make(map[string]oauth.GrantHandler)
		}
		s.customGrantHandlers[core.GrantTypeSAML2Bearer] = &saml2BearerHandler{server: s}
	}
}

type saml2BearerHandler struct {
	server *Server
}

func (h *saml2BearerHandler) GrantType() string {
	return core.GrantTypeSAML2Bearer
}

func (h *saml2BearerHandler) Handle(
	ctx core.HandlerContext, client *core.Client, req oauth.TokenRequest,
	dpopJKT, mtlsX5T string,
) {
	if req.Assertion == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	var scopes []string
	if req.Scope != "" {
		scopes = strings.Split(req.Scope, " ")
	}
	tokengrant.HandleSAML2BearerGrant(
		h.server, ctx, client, req.Assertion, scopes, req.Resource, dpopJKT, mtlsX5T,
	)
}
