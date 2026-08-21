package grpcserver

import (
	"context"
	"errors"

	"github.com/yangwb1123/snaplink/domains/permissions"
	authzv1 "github.com/yangwb1123/snaplink/gen/proto/authz/v1"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/metrics"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AuthzService implements authzv1.AuthorizerServer over a permissions.Provider.
type AuthzService struct {
	authzv1.UnimplementedAuthorizerServer
	provider permissions.Provider
	recorder *audit.Recorder
	metrics  *metrics.Metrics
	logger   spi.Logger
	boundary AuthzSessionBoundary
}

// AuthzSessionBoundary supplies the state needed to make session-scoped
// authorization decisions against the same identity boundary as the SSO
// server. Both dependencies are optional for embedded, stateless callers.
type AuthzSessionBoundary struct {
	SessionManager core.SessionManager
	ResolveSubject func(context.Context, string) (string, error)
}

func NewAuthzService(p permissions.Provider) *AuthzService {
	return NewAuthzServiceWithObservability(p, nil, nil, nil)
}

// NewAuthzServiceWithObservability wires optional decision-plane telemetry
// while preserving the original constructor for embedded callers.
func NewAuthzServiceWithObservability(p permissions.Provider, recorder *audit.Recorder, m *metrics.Metrics, logger spi.Logger) *AuthzService {
	return NewAuthzServiceWithSessionBoundary(p, recorder, m, logger, AuthzSessionBoundary{})
}

// NewAuthzServiceWithSessionBoundary adds optional session liveness and
// pairwise-subject resolution to the authorization decision path.
func NewAuthzServiceWithSessionBoundary(p permissions.Provider, recorder *audit.Recorder, m *metrics.Metrics, logger spi.Logger, boundary AuthzSessionBoundary) *AuthzService {
	return &AuthzService{provider: p, recorder: recorder, metrics: m, logger: logger, boundary: boundary}
}

func (s *AuthzService) Check(ctx context.Context, in *authzv1.CheckRequest) (*authzv1.CheckResponse, error) {
	if s.provider == nil {
		return nil, status.Error(codes.FailedPrecondition, "permission provider not configured")
	}
	if in.SubjectId == "" || in.Permission == "" {
		return nil, status.Error(codes.InvalidArgument, "subject_id and permission required")
	}
	perms, err := s.resolvePermissions(ctx, in)
	if err != nil && !errors.Is(err, permissions.ErrUserNotFound) {
		return nil, status.Errorf(codes.Internal, "permissions lookup: %v", err)
	}
	var allowed bool
	if in.ResourceType != "" {
		allowed, err = s.checkResource(in, perms)
		if err != nil {
			if status.Code(err) == codes.FailedPrecondition {
				return nil, err
			}
			return nil, status.Errorf(codes.Internal, "resource check: %v", err)
		}
	} else {
		allowed = permissions.Matches(perms, in.Permission)
	}
	s.recordDecision(ctx, in, allowed)
	return &authzv1.CheckResponse{Allowed: allowed}, nil
}

func (s *AuthzService) resolvePermissions(ctx context.Context, in *authzv1.CheckRequest) ([]permissions.Permission, error) {
	subject, err := s.resolveSessionSubject(ctx, in)
	if err != nil {
		return nil, err
	}
	if in.SessionId != "" {
		live, err := s.sessionIsLive(ctx, in, subject)
		if err != nil {
			return nil, err
		}
		if !live {
			return nil, nil
		}
		if activator, ok := s.provider.(permissions.SessionRoleActivator); ok {
			roles, err := activator.ActiveRoles(ctx, subject, in.ClientId, in.SessionId)
			if err != nil {
				return nil, err
			}
			// An explicitly supplied session ID opts into the active-role
			// projection. Empty means no active authority, not legacy full
			// assignment fallback; otherwise a logged-out/stale sid would
			// silently regain the subject's complete role set.
			return permissions.PermissionsFromRoles(roles), nil
		}
	}
	return s.provider.Permissions(ctx, subject, in.ClientId)
}

func (s *AuthzService) resolveSessionSubject(ctx context.Context, in *authzv1.CheckRequest) (string, error) {
	if in.SessionId == "" || s.boundary.ResolveSubject == nil {
		return in.SubjectId, nil
	}
	subject, err := s.boundary.ResolveSubject(ctx, in.SubjectId)
	if err != nil {
		return "", err
	}
	if subject == "" {
		return "", errors.New("authorization subject resolution returned an empty subject")
	}
	return subject, nil
}

func (s *AuthzService) sessionIsLive(ctx context.Context, in *authzv1.CheckRequest, subject string) (bool, error) {
	if s.boundary.SessionManager == nil {
		return true, nil
	}
	sess, err := s.boundary.SessionManager.Get(ctx, in.SessionId)
	if errors.Is(err, core.ErrSessionNotFound) || sess == nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if sess.Revoked || sess.IsExpired() || sess.UserID == "" || sess.UserID != subject {
		return false, nil
	}
	if sess.ClientID != "" && sess.ClientID != in.ClientId {
		return false, nil
	}
	return true, nil
}

func (s *AuthzService) checkResource(in *authzv1.CheckRequest, perms []permissions.Permission) (bool, error) {
	rp, ok := s.provider.(permissions.ResourceProvider)
	if !ok {
		return false, status.Error(codes.FailedPrecondition, "resource lookup requested but permission provider has no resource catalog")
	}
	return permissions.CheckResource(rp, &permissions.ResourceLookup{
		TenantID: in.TenantId,
		ClientID: in.ClientId,
		Type:     permissions.ResourceType(in.ResourceType),
		Match:    in.Attributes,
	}, perms, in.Permission)
}

func (s *AuthzService) recordDecision(ctx context.Context, in *authzv1.CheckRequest, allowed bool) {
	decision := "deny"
	outcome := audit.OutcomeFailure
	if allowed {
		decision = "allow"
		outcome = audit.OutcomeSuccess
	}
	if s.metrics != nil && s.metrics.AuthzChecksTotal != nil {
		s.metrics.AuthzChecksTotal.WithLabelValues(decision).Inc()
	}
	if s.recorder != nil {
		e := &audit.Event{Type: audit.EventPermissionCheck, Outcome: outcome, ActorID: in.SubjectId, ClientID: in.ClientId}
		audit.SetMeta(e, "permission", in.Permission)
		audit.SetMeta(e, "decision", decision)
		audit.SetMeta(e, "resource_type", in.ResourceType)
		s.recorder.Record(ctx, e)
	}
	if !allowed && s.logger != nil {
		s.logger.Info("authorization denied", "subject_id", in.SubjectId, "client_id", in.ClientId, "permission", in.Permission)
	}
}

func (s *AuthzService) ListPermissions(ctx context.Context, in *authzv1.SubjectRequest) (*authzv1.PermissionList, error) {
	if s.provider == nil {
		return nil, status.Error(codes.FailedPrecondition, "permission provider not configured")
	}
	perms, err := s.provider.Permissions(ctx, in.SubjectId, in.ClientId)
	if err != nil && !errors.Is(err, permissions.ErrUserNotFound) {
		return nil, status.Errorf(codes.Internal, "permissions lookup: %v", err)
	}
	out := &authzv1.PermissionList{Permissions: make([]*authzv1.Permission, 0, len(perms))}
	for _, p := range perms {
		out.Permissions = append(out.Permissions, &authzv1.Permission{Code: p.Code, Resource: p.Resource})
	}
	return out, nil
}

func (s *AuthzService) ListRoles(ctx context.Context, in *authzv1.SubjectRequest) (*authzv1.RoleList, error) {
	if s.provider == nil {
		return nil, status.Error(codes.FailedPrecondition, "permission provider not configured")
	}
	roles, err := s.provider.Roles(ctx, in.SubjectId, in.ClientId)
	if err != nil && !errors.Is(err, permissions.ErrUserNotFound) {
		return nil, status.Errorf(codes.Internal, "roles lookup: %v", err)
	}
	out := &authzv1.RoleList{Roles: make([]*authzv1.Role, 0, len(roles))}
	for _, r := range roles {
		out.Roles = append(out.Roles, &authzv1.Role{
			Code:        r.Code,
			Name:        r.Name,
			Description: r.Description,
			Permissions: append([]string{}, r.Permissions...),
		})
	}
	return out, nil
}

func (s *AuthzService) GetMenus(ctx context.Context, in *authzv1.SubjectRequest) (*authzv1.MenuTree, error) {
	if s.provider == nil {
		return nil, status.Error(codes.FailedPrecondition, "permission provider not configured")
	}
	tree, err := s.provider.Menus(ctx, in.SubjectId, in.ClientId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "menus lookup: %v", err)
	}
	return &authzv1.MenuTree{Items: convertMenuTree(tree)}, nil
}

func convertMenuTree(in permissions.MenuTree) []*authzv1.MenuItem {
	if len(in) == 0 {
		return nil
	}
	out := make([]*authzv1.MenuItem, 0, len(in))
	for _, m := range in {
		out = append(out, convertMenuItem(m))
	}
	return out
}

func convertMenuItem(in permissions.MenuItem) *authzv1.MenuItem {
	m := &authzv1.MenuItem{
		Id:         in.ID,
		Name:       in.Name,
		Path:       in.Path,
		Icon:       in.Icon,
		Permission: in.Permission,
		Children:   convertMenuTree(in.Children),
	}
	if len(in.Buttons) > 0 {
		m.Buttons = make([]*authzv1.Button, 0, len(in.Buttons))
		for _, b := range in.Buttons {
			m.Buttons = append(m.Buttons, &authzv1.Button{
				Code: b.Code, Name: b.Name, Permission: b.Permission,
			})
		}
	}
	return m
}
