package grpcadmin

import (
	"context"
	"errors"
	"sort"
	"strings"

	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
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

// List applies filter -> sort -> offset pagination over a full
// s.users.List(ctx) scan. See admin_paginate.go for why this bounds the
// RESPONSE but not the server-side materialization.
func (s *UserAdminService) List(ctx context.Context, in *adminv1.ListUsersRequest) (*adminv1.ListUsersResponse, error) {
	if s.users == nil {
		return nil, status.Error(codes.FailedPrecondition, "user provider not configured")
	}
	all, err := s.users.List(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list: %v", err)
	}
	all, err = filterUsers(all, in.GetFilter())
	if err != nil {
		return nil, err
	}
	if err = sortUsers(all, in.GetOrderBy()); err != nil {
		return nil, err
	}
	offset, err := decodeOffset(in.GetPageToken())
	if err != nil {
		return nil, err
	}
	lo, hi := pageBounds(offset, clampPageSize(in.GetPageSize()), len(all))
	out := &adminv1.ListUsersResponse{
		Users:         make([]*adminv1.User, 0, hi-lo),
		TotalSize:     int32(len(all)),
		NextPageToken: encodeOffset(hi, len(all)),
	}
	for _, u := range all[lo:hi] {
		out.Users = append(out.Users, userToProto(u))
	}
	return out, nil
}

// filterUsers narrows all to rows matching expr, or returns all unchanged
// when expr is empty. Field set is the STABLE proto-package contract:
// id/provider/external_id (exact) + name/email (substring).
func filterUsers(all []*sso.User, expr string) ([]*sso.User, error) {
	field, value, ok := parseAdminFilter(expr)
	if !ok {
		return all, nil
	}
	out := make([]*sso.User, 0, len(all))
	for _, u := range all {
		match, err := userMatches(u, field, value)
		if err != nil {
			return nil, err
		}
		if match {
			out = append(out, u)
		}
	}
	return out, nil
}

// userMatches evaluates one filter field against a user.
func userMatches(u *sso.User, field, value string) (bool, error) {
	switch strings.ToLower(field) {
	case "id":
		return u.ID == value, nil
	case "provider":
		return u.Provider == value, nil
	case "external_id":
		return u.ExternalID == value, nil
	case "name":
		return strings.Contains(strings.ToLower(u.Name), strings.ToLower(value)), nil
	case "email":
		return strings.Contains(strings.ToLower(u.Email), strings.ToLower(value)), nil
	default:
		return false, status.Errorf(codes.InvalidArgument, "unsupported filter field %q", field)
	}
}

// sortUsers orders all in place by order_by (default: id ascending, the
// MANDATORY stable sort that makes offset paging deterministic over the
// memory store's random map iteration).
func sortUsers(all []*sso.User, orderBy string) error {
	field, desc := parseOrderBy(orderBy)
	less, err := userLess(field)
	if err != nil {
		return err
	}
	sort.SliceStable(all, func(i, j int) bool {
		if desc {
			return less(all[j], all[i])
		}
		return less(all[i], all[j])
	})
	return nil
}

// userLess returns the comparator for one order_by field. Unlike
// clientLess, 'created_at' maps to the real core.User.CreatedAt field here
// (core.User has one; core.Client does not) — the documented order_by
// asymmetry between the two List RPCs.
func userLess(field string) (func(a, b *sso.User) bool, error) {
	switch strings.ToLower(field) {
	case "", "id":
		return func(a, b *sso.User) bool { return a.ID < b.ID }, nil
	case "created_at":
		return func(a, b *sso.User) bool { return a.CreatedAt.Before(b.CreatedAt) }, nil
	case "provider":
		return func(a, b *sso.User) bool { return a.Provider < b.Provider }, nil
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported order_by field %q", field)
	}
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
