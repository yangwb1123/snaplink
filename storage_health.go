package sso

import "github.com/snaplink/sso/internal/handler"

func WithStorageHealth(sources ...StorageHealthSource) Option {
	return func(s *Server) {
		for _, src := range sources {
			if src.Name == "" {
				continue
			}
			s.storageHealthSources = append(s.storageHealthSources, src)
		}
	}
}

func (s *Server) handleStorageHealth(ctx HandlerContext) {
	handler.HandleStorageHealth(s.BuildHandlerDeps(), ctx)
}
