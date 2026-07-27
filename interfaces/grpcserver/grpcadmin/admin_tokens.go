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

// ListSessions applies offset pagination over a full ListAll/ListByUser(ctx)
// scan. This proto has no order_by/filter fields, so the only thing to wire
// beyond pagination is a fixed deterministic sort (id ascending) — required
// because SessionManager backends are not contractually ordered. See
// admin_paginate.go for why this bounds the RESPONSE but not the server-side
// materialization.
func (s *TokenAdminService) ListSessions(ctx context.Context, in *adminv1.ListSessionsRequest) (*adminv1.ListSessionsResponse, error) {
	if s.sessions == nil {
		return nil, status.Error(codes.Unimplemented, "session manager not configured")
	}
	var all []*sso.Session
	var err error
	if in != nil && in.UserId != "" {
		all, err = s.sessions.ListByUser(ctx, in.UserId)
	} else {
		all, err = s.sessions.ListAll(ctx)
	}
	if err != nil {
		if errors.Is(err, sso.ErrUnsupportedOperation) {
			return nil, status.Error(codes.Unimplemented, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "list sessions: %v", err)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	offset, err := decodeOffset(in.GetPageToken())
	if err != nil {
		return nil, err
	}
	lo, hi := pageBounds(offset, clampPageSize(in.GetPageSize()), len(all))
	out := &adminv1.ListSessionsResponse{
		Sessions:      make([]*adminv1.SessionToken, 0, hi-lo),
		TotalSize:     int32(len(all)),
		NextPageToken: encodeOffset(hi, len(all)),
	}
	for _, sn := range all[lo:hi] {
		out.Sessions = append(out.Sessions, &adminv1.SessionToken{
			Id:            sn.ID,
			UserId:        sn.UserID,
			CreatedAtUnix: sn.CreatedAt.Unix(),
			ExpiresAtUnix: sn.ExpiresAt.Unix(),
		})
	}
	return out, nil
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
	recordAdmin(ctx, s.recorder, audit.EventAdminTempTokenIssued, in.UserId)
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
