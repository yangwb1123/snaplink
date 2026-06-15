package handler

import (
	"context"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/spi"
)

// ServerDeps is the interface handler functions use to access Server
// configuration and state. Grows incrementally as files are moved.
type ServerDeps interface {
	SrvLogger() spi.Logger
}

// HandlerContext is an alias to keep handler signatures consistent.
type HandlerContext = core.HandlerContext

// StorageHealthSource describes one wired store for the storage-health report.
type StorageHealthSource struct {
	Name           string
	Ping           func(ctx context.Context) error
	SchemaVersions func(ctx context.Context) (map[string]int, error)
}

// StorageHealthDeps is the interface for storage health handlers.
type StorageHealthDeps interface {
	StorageHealthSources() []StorageHealthSource
}
