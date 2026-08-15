package grpcadmin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/operations"
	"github.com/yangwb1123/snaplink/shared/core"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const defaultTempTokenLen = 32

// TokenAdminService is the admin surface for tokens. Wraps a SessionManager
// for List/Revoke and a TempTokenStore for IssueTempToken. Either dependency
// may be nil — those RPCs respond Unimplemented when the backend is absent.
type TokenAdminService struct {
	adminv1.UnimplementedTokenAdminServiceServer
	sessions     sso.SessionManager
	tempStore    authenticators.TempTokenStore
	tempTokenTTL time.Duration
	issuers      map[string]sso.TokenIssuer // name -> issuer; for Revoke fan-out
	// revokeAcrossIssuers, when wired, revokes AND publishes the revocation on
	// the cluster Bus (KindTokenRevoked) so peer replicas drop the token too.
	// Without it, Revoke only mutates this replica's in-process deny-set, so a
	// break-glass admin revoke on an N-replica fleet leaves the token valid on
	// every other replica until its natural exp.
	revokeAcrossIssuers func(context.Context, string) (revoked, failed []string)
	recorder            *audit.Recorder
}

// TokenAdminConfig bundles the dependencies for NewTokenAdminService.
// All fields optional; missing capabilities surface as Unimplemented.
type TokenAdminConfig struct {
	Sessions     sso.SessionManager
	TempStore    authenticators.TempTokenStore
	TempTokenTTL time.Duration
	Issuers      map[string]sso.TokenIssuer
	// RevokeAcrossIssuers is the cross-replica-publishing revoke seam
	// (sso.Server.RevokeAcrossIssuers). When set, Revoke uses it so a revocation
	// propagates to peer replicas; when nil, Revoke falls back to a local-only
	// issuer fan-out (single-replica / embedder builds).
	RevokeAcrossIssuers func(context.Context, string) (revoked, failed []string)
	Recorder            *audit.Recorder
}

func NewTokenAdminService(cfg TokenAdminConfig) *TokenAdminService {
	ttl := cfg.TempTokenTTL
	if ttl <= 0 {
		ttl = authenticators.DefaultTempTokenTTL
	}
	return &TokenAdminService{
		sessions:            cfg.Sessions,
		tempStore:           cfg.TempStore,
		tempTokenTTL:        ttl,
		issuers:             cfg.Issuers,
		revokeAcrossIssuers: cfg.RevokeAcrossIssuers,
		recorder:            cfg.Recorder,
	}
}

// ListSessions dispatches through runListPage (admin_paginate.go): keyset
// pushdown when the session manager implements core.PaginatedSessionLister
// (userID "" = ListAll, non-empty = ListByUser), else the legacy
// ListAll/ListByUser(ctx) -> fixed id-ascending sort -> offset slice. This
// proto has no order_by/filter fields, so the only thing to wire beyond
// pagination is the fixed deterministic sort — required because
// SessionManager backends are not contractually ordered.
func (s *TokenAdminService) ListSessions(ctx context.Context, in *adminv1.ListSessionsRequest) (*adminv1.ListSessionsResponse, error) {
	if s.sessions == nil {
		return nil, status.Error(codes.Unimplemented, "session manager not configured")
	}
	userID := ""
	if in != nil {
		userID = in.UserId
	}
	var ext pageLister[*sso.Session]
	if p, ok := s.sessions.(core.PaginatedSessionLister); ok {
		ext = sessionPageLister{inner: p, userID: userID}
	}
	items, next, total, err := runListPage(ctx,
		in.GetPageToken(), in.GetPageSize(), "", "",
		ext,
		func(ctx context.Context) ([]*sso.Session, error) { return s.listSessionsAll(ctx, userID) },
		func(items []*sso.Session, _ string) ([]*sso.Session, error) {
			sort.Slice(items, func(i, j int) bool { return core.CompareSessions(items[i], items[j]) < 0 })
			return items, nil
		},
		nil, "list sessions: %v", nil,
	)
	if err != nil {
		return nil, err
	}
	return &adminv1.ListSessionsResponse{
		Sessions:      sessionTokens(items),
		TotalSize:     total,
		NextPageToken: next,
	}, nil
}

// listSessionsAll materializes the session list, mapping an unsupported
// backend to Unimplemented exactly as the pre-pagination path did.
func (s *TokenAdminService) listSessionsAll(ctx context.Context, userID string) ([]*sso.Session, error) {
	var all []*sso.Session
	var err error
	if userID != "" {
		all, err = s.sessions.ListByUser(ctx, userID)
	} else {
		all, err = s.sessions.ListAll(ctx)
	}
	if err != nil {
		if errors.Is(err, sso.ErrUnsupportedOperation) {
			return nil, status.Error(codes.Unimplemented, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "list sessions: %v", err)
	}
	return all, nil
}

// sessionTokens projects sessions onto the wire SessionToken shape.
func sessionTokens(items []*sso.Session) []*adminv1.SessionToken {
	out := make([]*adminv1.SessionToken, 0, len(items))
	for _, sn := range items {
		out = append(out, &adminv1.SessionToken{
			Id:            sn.ID,
			UserId:        sn.UserID,
			CreatedAtUnix: sn.CreatedAt.Unix(),
			ExpiresAtUnix: sn.ExpiresAt.Unix(),
		})
	}
	return out
}

func (s *TokenAdminService) Revoke(ctx context.Context, in *adminv1.RevokeRequest) (*adminv1.RevokeResponse, error) {
	if in == nil || (in.Token == "" && in.SessionId == "") {
		return nil, status.Error(codes.InvalidArgument, "token or session_id required")
	}
	revoked := make([]string, 0, 2)
	if in.SessionId != "" {
		if s.sessions == nil {
			return nil, status.Error(codes.FailedPrecondition, "session manager not configured")
		}
		if err := s.sessions.Destroy(ctx, in.SessionId); err == nil {
			revoked = append(revoked, sso.RevokedSession)
		} else if !errors.Is(err, sso.ErrSessionNotFound) {
			return nil, status.Errorf(codes.Internal, "destroy session: %v", err)
		}
	}
	if in.Token != "" {
		// Prefer the cross-replica-publishing seam so a break-glass revoke takes
		// effect fleet-wide, not just on the replica that served this RPC.
		if s.revokeAcrossIssuers != nil {
			if hit, _ := s.revokeAcrossIssuers(ctx, in.Token); len(hit) > 0 {
				revoked = append(revoked, sso.RevokedToken)
			}
		} else if len(s.issuers) > 0 {
			// Local-only fallback (no publish seam wired): any issuer that
			// recognizes the token wins.
			for _, iss := range s.issuers {
				if err := iss.Revoke(ctx, in.Token); err == nil {
					revoked = append(revoked, sso.RevokedToken)
					break
				}
			}
		}
	}
	if len(revoked) == 0 {
		return nil, status.Error(codes.NotFound, "nothing revoked")
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminTokenRevoked, in.SessionId+"|"+in.Token[:min(8, len(in.Token))])
	return &adminv1.RevokeResponse{Revoked: revoked}, nil
}

func (s *TokenAdminService) IssueTempToken(ctx context.Context, in *adminv1.IssueTempTokenRequest) (*adminv1.IssueTempTokenResponse, error) {
	if s.tempStore == nil {
		return nil, status.Error(codes.Unimplemented, "temp token store not configured")
	}
	if in == nil || in.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id required")
	}
	token, err := generateTempToken(defaultTempTokenLen)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "rand: %v", err)
	}
	claims := map[string]string{}
	if in.ClientId != "" {
		claims["aud"] = in.ClientId
	}
	if len(in.Scopes) > 0 {
		claims["scope"] = strings.Join(in.Scopes, " ")
	}
	sub := &sso.Subject{ID: in.UserId, Claims: claims}
	if err := s.tempStore.Issue(ctx, token, sub, s.tempTokenTTL); err != nil {
		return nil, status.Errorf(codes.Internal, "issue temp: %v", err)
	}
	recordAdminMeta(ctx, s.recorder, audit.EventAdminTempTokenIssued, in.UserId,
		map[string]string{"target_user_id": in.UserId})
	return &adminv1.IssueTempTokenResponse{
		Token:         token,
		ExpiresAtUnix: time.Now().Add(s.tempTokenTTL).Unix(),
	}, nil
}

func generateTempToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
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

// ListOperations lists durable operations with real pagination. Extension
// path (store implements operations.PaginatedOperationStore): keyset pages
// in the new deterministic id-ascending order. Fallback: today's store-order
// list, now offset-paginated — the response ORDER is unchanged (only the
// extension path reorders).
func (s *OperationAdminService) ListOperations(
	ctx context.Context, in *adminv1.ListOperationsRequest,
) (*adminv1.ListOperationsResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "operation store not configured")
	}
	var ext pageLister[operations.Operation]
	if p, ok := s.store.(operations.PaginatedOperationStore); ok {
		ext = p
	}
	items, next, total, err := runListPage(ctx,
		in.GetPageToken(), in.GetPageSize(), "", "",
		ext,
		func(ctx context.Context) ([]operations.Operation, error) {
			items, err := s.store.List(ctx)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "list operations: %v", err)
			}
			return items, nil
		},
		func(items []operations.Operation, _ string) ([]operations.Operation, error) {
			return items, nil // fallback keeps today's store order
		},
		nil, "list operations: %v", nil,
	)
	if err != nil {
		return nil, err
	}
	out := &adminv1.ListOperationsResponse{
		Operations:    make([]*adminv1.AdminOperation, 0, len(items)),
		NextPageToken: next,
		TotalSize:     total,
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
