package grpcadmin

import (
	"context"
	"errors"
	"sort"
	"strings"

	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UserAdminService implements admin CRUD over a sso.UserProvider plus
// session listing via sso.SessionManager. CreateOrUpdate is split into
// Create (rejects existing IDs) and Update (rejects missing IDs).
type UserAdminService struct {
	adminv1.UnimplementedUserAdminServiceServer
	users    sso.UserProvider
	sessions sso.SessionManager // optional; ListUserSessions returns Unimplemented when nil
	recorder *audit.Recorder
}

func NewUserAdminService(users sso.UserProvider, sessions sso.SessionManager, recorder *audit.Recorder) *UserAdminService {
	return &UserAdminService{users: users, sessions: sessions, recorder: recorder}
}

// List dispatches through runListPage (admin_paginate.go): keyset pushdown
// when the user provider implements core.PaginatedUserProvider, else the
// legacy List(ctx) -> filter -> sort -> offset-slice path.
func (s *UserAdminService) List(ctx context.Context, in *adminv1.ListUsersRequest) (*adminv1.ListUsersResponse, error) {
	if s.users == nil {
		return nil, status.Error(codes.FailedPrecondition, "user provider not configured")
	}
	var ext pageLister[*sso.User]
	if p, ok := s.users.(core.PaginatedUserProvider); ok {
		ext = p
	}
	items, next, total, err := runListPage(ctx,
		in.GetPageToken(), in.GetPageSize(), in.GetOrderBy(), in.GetFilter(),
		ext,
		func(ctx context.Context) ([]*sso.User, error) { return s.users.List(ctx) },
		func(items []*sso.User, orderBy string) ([]*sso.User, error) {
			items, err := filterUsers(items, in.GetFilter())
			if err != nil {
				return nil, err
			}
			if err := sortUsers(items, orderBy); err != nil {
				return nil, err
			}
			return items, nil
		},
		validateListSpecUser,
		"list: %v",
		nil,
	)
	if err != nil {
		return nil, err
	}
	out := &adminv1.ListUsersResponse{
		Users:         make([]*adminv1.User, 0, len(items)),
		TotalSize:     total,
		NextPageToken: next,
	}
	for _, u := range items {
		out.Users = append(out.Users, userToProto(u))
	}
	return out, nil
}

// filterUsers narrows all to rows matching expr, or returns all unchanged
// when expr is empty, via the shared core matcher. Field set is the STABLE
// proto-package contract: id/provider/external_id (exact) + name/email
// (substring).
func filterUsers(all []*sso.User, expr string) ([]*sso.User, error) {
	field, value, ok := core.ParseFilterExpr(expr)
	if !ok {
		return all, nil
	}
	out := make([]*sso.User, 0, len(all))
	for _, u := range all {
		match, err := core.UserMatches(u, field, value)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		if match {
			out = append(out, u)
		}
	}
	return out, nil
}

// sortUsers orders all in place by order_by (default: id ascending, the
// MANDATORY stable sort that makes offset paging deterministic over the
// memory store's random map iteration). Field validation + comparison come
// from core so the fallback and the extension store cannot drift.
func sortUsers(all []*sso.User, orderBy string) error {
	field, desc := parseOrderBy(orderBy)
	if err := core.ValidateUserOrderBy(field); err != nil {
		return status.Errorf(codes.InvalidArgument, "%v", err)
	}
	sort.SliceStable(all, func(i, j int) bool {
		if desc {
			return core.CompareUsers(all[j], all[i], field) < 0
		}
		return core.CompareUsers(all[i], all[j], field) < 0
	})
	return nil
}

func (s *UserAdminService) Get(ctx context.Context, in *adminv1.GetUserRequest) (*adminv1.GetUserResponse, error) {
	if s.users == nil {
		return nil, status.Error(codes.FailedPrecondition, "user provider not configured")
	}
	if in == nil || in.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	u, err := s.users.GetByID(ctx, in.Id)
	if errors.Is(err, sso.ErrNoSuchUser) {
		return nil, status.Error(codes.NotFound, "user not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get: %v", err)
	}
	return &adminv1.GetUserResponse{User: userToProto(u)}, nil
}

func (s *UserAdminService) Create(ctx context.Context, in *adminv1.CreateUserRequest) (*adminv1.CreateUserResponse, error) {
	if s.users == nil {
		return nil, status.Error(codes.FailedPrecondition, "user provider not configured")
	}
	if in == nil || in.User == nil || in.User.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "user.id required")
	}
	// Reject if already present — CreateOrUpdate would silently overwrite.
	if _, err := s.users.GetByID(ctx, in.User.Id); err == nil {
		return nil, status.Error(codes.AlreadyExists, "user already exists")
	}
	u := protoToUser(in.User)
	if err := s.users.CreateOrUpdate(ctx, u); err != nil {
		return nil, status.Errorf(codes.Internal, "create: %v", err)
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminUserCreated, u.ID)
	return &adminv1.CreateUserResponse{User: userToProto(u)}, nil
}

func (s *UserAdminService) Update(ctx context.Context, in *adminv1.UpdateUserRequest) (*adminv1.UpdateUserResponse, error) {
	if s.users == nil {
		return nil, status.Error(codes.FailedPrecondition, "user provider not configured")
	}
	if in == nil || in.User == nil || in.User.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "user.id required")
	}
	existing, err := s.users.GetByID(ctx, in.User.Id)
	if err != nil {
		if errors.Is(err, sso.ErrNoSuchUser) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Errorf(codes.Internal, "lookup: %v", err)
	}
	u := applyProtoToExistingUser(existing, in.User)
	if err := s.users.CreateOrUpdate(ctx, u); err != nil {
		return nil, status.Errorf(codes.Internal, "update: %v", err)
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminUserUpdated, u.ID)
	return &adminv1.UpdateUserResponse{User: userToProto(u)}, nil
}

func (s *UserAdminService) Delete(ctx context.Context, in *adminv1.DeleteUserRequest) (*adminv1.DeleteUserResponse, error) {
	if s.users == nil {
		return nil, status.Error(codes.FailedPrecondition, "user provider not configured")
	}
	if in == nil || in.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	if err := s.users.Delete(ctx, in.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "delete: %v", err)
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminUserDeleted, in.Id)
	return &adminv1.DeleteUserResponse{}, nil
}

func (s *UserAdminService) ListUserSessions(ctx context.Context, in *adminv1.ListUserSessionsRequest) (*adminv1.ListUserSessionsResponse, error) {
	if s.sessions == nil {
		return nil, status.Error(codes.Unimplemented, "session manager not configured")
	}
	if in == nil || in.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	all, err := s.sessions.ListByUser(ctx, in.Id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list sessions: %v", err)
	}
	out := &adminv1.ListUserSessionsResponse{Sessions: make([]*adminv1.Session, 0, len(all))}
	for _, sn := range all {
		out.Sessions = append(out.Sessions, sessionToProto(sn))
	}
	return out, nil
}

// adminUserAttrDenylist holds User.Attributes keys containing credential
// material that must never be forwarded to callers. Matches the keys used by
// interfaces/snapshot and protocols/compliance so all serialization surfaces
// are consistent. A denylist (not an allowlist) is used here because admin
// callers legitimately need custom attributes.
var adminUserAttrDenylist = []string{"password_hash", "password_hash_format", "seeded_password"}

// redactAdminUserAttrs returns a copy of attrs with credential keys removed.
// Returns nil when the cleaned result is empty.
func redactAdminUserAttrs(attrs map[string]string) map[string]string {
	if len(attrs) == 0 {
		return nil
	}
	out := make(map[string]string, len(attrs))
	for k, v := range attrs {
		out[k] = v
	}
	for _, k := range adminUserAttrDenylist {
		delete(out, k)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func userToProto(u *sso.User) *adminv1.User {
	if u == nil {
		return nil
	}
	return &adminv1.User{
		Id:         u.ID,
		ExternalId: u.ExternalID,
		Provider:   u.Provider,
		Attributes: redactAdminUserAttrs(u.Attributes),
	}
}

func protoToUser(in *adminv1.User) *sso.User {
	if in == nil {
		return nil
	}
	return &sso.User{
		ID:         in.Id,
		ExternalID: in.ExternalId,
		Provider:   in.Provider,
		Attributes: in.Attributes,
	}
}

// applyProtoToExistingUser overlays the admin proto's wire-representable
// fields onto a COPY of the existing user, so every core.User field NOT in
// the admin.v1.User message (Email, Username, Name, DisplayName, CreatedAt)
// survives an Update untouched — the same fix as
// applyProtoToExistingClient (admin_clients.go) for the identical bug
// class: Update previously built the new record from protoToUser's blank
// User, silently zeroing every field the wire contract doesn't carry.
// UpdatedAt is left to the store's own CreateOrUpdate to stamp.
func applyProtoToExistingUser(existing *sso.User, in *adminv1.User) *sso.User {
	u := *existing
	u.ID = in.Id
	u.ExternalID = in.ExternalId
	u.Provider = in.Provider
	u.Attributes = in.Attributes
	return &u
}

func sessionToProto(s *sso.Session) *adminv1.Session {
	if s == nil {
		return nil
	}
	return &adminv1.Session{
		Id:            s.ID,
		UserId:        s.UserID,
		CreatedAtUnix: s.CreatedAt.Unix(),
		ExpiresAtUnix: s.ExpiresAt.Unix(),
		Revoked:       s.Revoked,
	}
}

func parseAdminFilter(expr string) (field, value string, ok bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return "", "", false
	}
	if idx := strings.Index(expr, ":"); idx >= 0 {
		return strings.TrimSpace(expr[:idx]), strings.TrimSpace(expr[idx+1:]), true
	}
	if parts := strings.SplitN(expr, " eq ", 2); len(parts) == 2 {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
	}
	return "", expr, true
}

// parseOrderBy strips a leading '-' (descending) from an order_by field.
func parseOrderBy(s string) (field string, desc bool) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "-") {
		return strings.TrimSpace(s[1:]), true
	}
	return s, false
}

// --- Keyset pagination dispatch (extension path) ---
//
// Every List RPC shrinks to: nil-check -> clamp page size -> runListPage ->
// proto-convert the returned window. runListPage takes the store's optional
// pagination SPI when implemented (keyset pushdown with a MAC-bound cursor
// token), and otherwise runs today's listAll -> filter/sort -> offset-slice
// path byte-identically. All new pagination code lives in this file to stay
// at the package's 10-file fan-out cap; the codec lives in shared/security.

// pageLister is the uniform grpcadmin-side shape of every optional
// pagination SPI (core.PaginatedClientStore, tenant.PaginatedTenantStore,
// ...): one concrete, non-generic method per entity.
type pageLister[T any] interface {
	ListPage(ctx context.Context, q core.PageQuery) ([]T, []byte, int, error)
}

// sessionPageLister adapts the userID-scoped core.PaginatedSessionLister to
// pageLister. userID "" = every session (ListAll); non-empty = that user's
// (ListByUser).
type sessionPageLister struct {
	inner  core.PaginatedSessionLister
	userID string
}

// validateListSpec runs the row-independent spec check every extension path
// shares: filter field membership + ParseBool, then order_by membership.
// The validator closures come from the entity home packages (single-sourced
// error strings, byte-identical to the fallback matchers' output). nil
// validators = entity has no filter/order_by surface (sessions, domains,
// roles, assignments, releases, snapshots, operations).
func validateListSpec(filter, orderBy string, validateFilter func(field, value string) error, validateOrder func(field string) error) error {
	if validateFilter != nil {
		if field, value, ok := core.ParseFilterExpr(filter); ok {
			if err := validateFilter(field, value); err != nil {
				return status.Errorf(codes.InvalidArgument, "%v", err)
			}
		}
	}
	if validateOrder != nil {
		field, _ := parseOrderBy(orderBy)
		if err := validateOrder(field); err != nil {
			return status.Errorf(codes.InvalidArgument, "%v", err)
		}
	}
	return nil
}

func validateListSpecUser(filter, orderBy string) error {
	return validateListSpec(filter, orderBy, core.ValidateUserFilter, core.ValidateUserOrderBy)
}
