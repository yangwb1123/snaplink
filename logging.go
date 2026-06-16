package sso

import (
	"context"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/internal/handler"
)

func (s *Server) logErrorCtx(ctx core.HandlerContext, msg string, kv ...any) {
	handler.LogErrorCtx(s.BuildHandlerDeps(), ctx, msg, kv...)
}

func (s *Server) traceContext(ctx core.HandlerContext) context.Context {
	return handler.TraceContext(ctx.Request())
}
