package grpcadmin

import (
	"context"
	"encoding/base64"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/operations"
	"github.com/yangwb1123/snaplink/shared/security/clientrotation"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// defaultAdminPageSize/maxAdminPageSize bound every List RPC in this package
// (ClientAdmin, UserAdmin, TenantAdmin, PermissionAdmin, TokenAdmin,
// SnapshotAdmin, ReleaseAdmin). This shim paginates AFTER a full
// store.List(ctx) — it bounds the gRPC RESPONSE, not the store-side
// materialization, so a >10K-row store still pays a full in-memory scan per
// page. The correct fix for that is an OPTIONAL store extension type-asserted
// at this layer (mirroring the existing core.TenantScopedClientStore
// precedent: try an efficient path, fall back to List()) — e.g. a future
// core.PaginatedClientStore / core.PaginatedUserProvider. Deferred; out of
// scope here.
const (
	defaultAdminPageSize = 100
	maxAdminPageSize     = 1000
	defaultExpiryWindow  = 30 * 24 * time.Hour
	maxClientLifetime    = 100 * 365 * 24 * time.Hour
)

// ListExpiring returns confidential clients with a persisted expiry no later
// than the requested horizon. Legacy/public clients (zero expiry) are omitted.
func (s *ClientAdminService) ListExpiring(ctx context.Context, in *adminv1.ListExpiringClientsRequest) (*adminv1.ListExpiringClientsResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "client store not configured")
	}
	window, err := expiryWindow(in)
	if err != nil {
		return nil, err
	}
	all, err := s.store.List(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list expiring clients: %v", err)
	}
	cutoff := time.Now().Add(window)
	var expiring []*sso.Client
	for _, client := range all {
		if !client.SecretExpiresAt.IsZero() && !client.SecretExpiresAt.After(cutoff) {
			expiring = append(expiring, client)
		}
	}
	sort.Slice(expiring, func(i, j int) bool {
		if expiring[i].SecretExpiresAt.Equal(expiring[j].SecretExpiresAt) {
			return expiring[i].ID < expiring[j].ID
		}
		return expiring[i].SecretExpiresAt.Before(expiring[j].SecretExpiresAt)
	})
	out := &adminv1.ListExpiringClientsResponse{Clients: make([]*adminv1.Client, 0, len(expiring))}
	for _, client := range expiring {
		out.Clients = append(out.Clients, clientToProto(client, false))
	}
	return out, nil
}

func expiryWindow(in *adminv1.ListExpiringClientsRequest) (time.Duration, error) {
	if in == nil || in.WithinSeconds == 0 {
		return defaultExpiryWindow, nil
	}
	if in.WithinSeconds < 0 || in.WithinSeconds > int64(maxClientLifetime/time.Second) {
		return 0, status.Error(codes.InvalidArgument, "within_seconds must be between 1 and 100 years")
	}
	return time.Duration(in.WithinSeconds) * time.Second, nil
}

func clientRotationPolicy(in *adminv1.RotateSecretRequest) (time.Duration, time.Duration, error) {
	maxSeconds := int64(maxClientLifetime / time.Second)
	if in.OverlapSeconds < 0 || in.LifetimeSeconds < 0 ||
		in.OverlapSeconds > maxSeconds || in.LifetimeSeconds > maxSeconds {
		return 0, 0, status.Error(codes.InvalidArgument, "rotation durations must be between 0 and 100 years")
	}
	overlap := clientrotation.DefaultOverlap
	if in.OverlapSeconds != 0 {
		overlap = time.Duration(in.OverlapSeconds) * time.Second
	}
	lifetime := clientrotation.DefaultLifetime
	if in.LifetimeSeconds != 0 {
		lifetime = time.Duration(in.LifetimeSeconds) * time.Second
	}
	if overlap < time.Hour || lifetime <= overlap {
		return 0, 0, status.Error(codes.InvalidArgument, "rotation policy requires overlap >= 1h and lifetime > overlap (max 100 years)")
	}
	return overlap, lifetime, nil
}

// clampPageSize maps a proto page_size (0 = unset) onto [1, maxAdminPageSize].
func clampPageSize(req int32) int {
	if req <= 0 {
		return defaultAdminPageSize
	}
	if req > maxAdminPageSize {
		return maxAdminPageSize
	}
	return int(req)
}

// decodeOffset decodes an opaque page_token into a decimal slice offset. The
// proto treats the token as opaque, so any decode failure — including a
// negative offset, which can only arise from a tampered/foreign token — is
// reported identically as an invalid page_token.
func decodeOffset(token string) (int, error) {
	if token == "" {
		return 0, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return 0, status.Error(codes.InvalidArgument, "invalid page_token")
	}
	off, err := strconv.Atoi(string(raw))
	if err != nil || off < 0 {
		return 0, status.Error(codes.InvalidArgument, "invalid page_token")
	}
	return off, nil
}

// encodeOffset returns the token for the next page, or "" once the caller
// has reached the end of the (filtered) result set.
func encodeOffset(next, total int) string {
	if next >= total {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(next)))
}

// pageBounds clamps offset/size against total, returning a valid [lo, hi)
// slice window. An offset beyond total yields an empty (but still valid)
// window rather than an error — paging past the end is not a client error.
func pageBounds(offset, size, total int) (lo, hi int) {
	if offset > total {
		offset = total
	}
	hi = offset + size
	if hi > total {
		hi = total
	}
	return offset, hi
}

// parseAdminFilter splits the proto's tiny 'field:value' | 'field eq value'
// filter mini-grammar. An empty expr means "match all" (ok=false signals the
// caller to skip filtering, not an error). A non-empty expr that matches
// neither form yields field="" with ok=true — every entity matcher's field
// switch treats an unrecognized field as InvalidArgument, so a malformed
// filter is rejected rather than silently ignored (STRICT: "bad filter
// value" must error, only a genuinely absent filter matches all).
// Deliberately NOT the SCIM RFC 7644 filter grammar (protocols/scim/filter.go)
// — that parser is unexported, HTTP-request-shaped, and far heavier than
// this proto's mini-grammar warrants; importing protocols/scim here would
// add coupling for no benefit.
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

// recordAdmin / recordAdminMeta below were formerly admin_shared.go, folded
// in here (rather than kept as an 11th file) to stay at the directory's
// 10-file maintainability cap (directory_fanout_test.go) once ListTenants'
// filter/sort support and the split-out admin_domains.go needed a slot.
// Both this file and the audit helpers below are cross-cutting infra used by
// every *AdminService in the package, unlike the other files here which each
// own one service's CRUD — that shared-infra nature is what makes the pairing
// cohesive rather than arbitrary.

// recordAdmin writes one audit event with the ActorID + IP + UA derived from
// the gRPC context. The admin interceptor in the sso package stashes the
// actor's userID + clientID via sso.AdminActorFromContext; we read it back
// here. Safe to call with a nil recorder — checking saves work.
func recordAdmin(ctx context.Context, recorder *audit.Recorder, t audit.EventType, target string) {
	recordAdminMeta(ctx, recorder, t, target, nil)
}

// recordAdminMeta is recordAdmin's metadata-carrying variant — same
// actor/target/context derivation, plus caller-supplied SetMeta entries for
// events needing more than the generic "target=<resource>" Reason (e.g. the
// client-registration review workflow's rejection reason and the rejected
// client's name, captured here since the record is gone after Delete).
func recordAdminMeta(ctx context.Context, recorder *audit.Recorder, t audit.EventType, target string, meta map[string]string) {
	if recorder == nil {
		return
	}
	evt := &audit.Event{
		Type:      t,
		Outcome:   audit.OutcomeSuccess,
		Timestamp: time.Now().UTC(),
		Reason:    "target=" + target,
	}
	if userID, clientID, ok := sso.AdminActorFromContext(ctx); ok {
		evt.ActorID = userID
		evt.ClientID = clientID
	}
	if p, ok := peer.FromContext(ctx); ok && p != nil {
		evt.ActorIP = p.Addr.String()
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if ua := md.Get("user-agent"); len(ua) > 0 {
			evt.UserAgent = ua[0]
		}
	}
	for k, v := range meta {
		audit.SetMeta(evt, k, v)
	}
	recorder.Record(ctx, evt)
}

type OperationAdminService struct {
	adminv1.UnimplementedOperationAdminServiceServer
	store operations.Store
}

func NewOperationAdminService(store operations.Store) *OperationAdminService {
	return &OperationAdminService{store: store}
}

func (s *OperationAdminService) GetOperation(
	ctx context.Context, in *adminv1.GetOperationRequest,
) (*adminv1.GetOperationResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "operation store not configured")
	}
	if in == nil || in.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	operation, err := s.store.Get(ctx, in.Id)
	if errors.Is(err, operations.ErrNotFound) {
		return nil, status.Error(codes.NotFound, "operation not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get operation: %v", err)
	}
	return &adminv1.GetOperationResponse{Operation: operationToProto(operation)}, nil
}

func (s *OperationAdminService) ListOperations(
	ctx context.Context, _ *adminv1.ListOperationsRequest,
) (*adminv1.ListOperationsResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "operation store not configured")
	}
	items, err := s.store.List(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list operations: %v", err)
	}
	out := &adminv1.ListOperationsResponse{
		Operations: make([]*adminv1.AdminOperation, 0, len(items)),
	}
	for _, operation := range items {
		out.Operations = append(out.Operations, operationToProto(operation))
	}
	return out, nil
}

func operationToProto(operation operations.Operation) *adminv1.AdminOperation {
	out := &adminv1.AdminOperation{
		Id: operation.ID, Kind: operation.Kind, Target: operation.Target,
		State: operation.State, CurrentStep: operation.CurrentStep,
		ResultJson: append([]byte(nil), operation.ResultJSON...), Error: operation.Error,
		CreatedAtUnix: operation.CreatedAt.Unix(), UpdatedAtUnix: operation.UpdatedAt.Unix(),
		Steps:         make([]*adminv1.OperationStep, 0, len(operation.Steps)),
		Compensations: make([]*adminv1.OperationStep, 0, len(operation.Compensations)),
	}
	for _, step := range operation.Steps {
		out.Steps = append(out.Steps, operationStepToProto(step))
	}
	for _, step := range operation.Compensations {
		out.Compensations = append(out.Compensations, operationStepToProto(step))
	}
	return out
}

func operationStepToProto(step operations.Step) *adminv1.OperationStep {
	out := &adminv1.OperationStep{Name: step.Name, State: step.State, Error: step.Error}
	if !step.StartedAt.IsZero() {
		out.StartedAtUnix = step.StartedAt.Unix()
	}
	if !step.FinishedAt.IsZero() {
		out.FinishedAtUnix = step.FinishedAt.Unix()
	}
	return out
}

func operationFailureError(operation operations.Operation, cause error) error {
	st := status.Convert(cause)
	withDetails, err := st.WithDetails(&errdetails.ErrorInfo{
		Reason: "OPERATION_FAILED",
		Metadata: map[string]string{
			"operation_id":  operation.ID,
			"operation_url": "/api/v1/admin/operations/" + operation.ID,
		},
	})
	if err != nil {
		return cause
	}
	return withDetails.Err()
}
