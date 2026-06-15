package sso

import (
	"context"

	"github.com/snaplink/sso/cluster"
	"github.com/snaplink/sso/internal/handler"
)

func (s *Server) publishTokenRevocation(ctx context.Context, token string, exp int64) {
	handler.PublishTokenRevocation(s, ctx, token, exp)
}

func (s *Server) applyTokenRevocation(ctx context.Context, evt cluster.Event) {
	handler.ApplyTokenRevocation(s, ctx, evt)
}

func jwtExpUnsafe(token string) int64 {
	return handler.JWTExpUnsafe(token)
}
