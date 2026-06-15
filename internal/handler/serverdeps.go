package handler

import (
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
