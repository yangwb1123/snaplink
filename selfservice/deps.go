package selfservice

import (
	"context"
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/spi"
)

// Deps defines the dependencies needed for self-service operations.
// *sso.Server satisfies this interface via accessor methods.
type Deps interface {
	// User management
	UserProvider() core.UserProvider
	PasswordCredentialStore() core.PasswordCredentialStore

	// Token stores
	PasswordResetStore() core.PasswordResetStore

	// Configuration
	EmailChangeTTL() time.Duration
	PasswordResetTTL() time.Duration

	// Password reset delivery
	PasswordResetResolver() func(ctx context.Context, identifier string) (string, error)
	PasswordResetDeliveryResolver() func(ctx context.Context, userID string) (string, error)
	PasswordResetSender() spi.PasswordResetSender

	// Email change delivery
	EmailChangeSender() spi.EmailChangeSender
	EmailChangeStore() core.EmailChangeStore

	// Session management
	SessionManager() core.SessionManager

	// Audit and logging
	Auditor() *audit.Recorder
	Logger() spi.Logger

	// Helper methods
	GenerateAuthCodeBytes() (string, error)
	TokenNoStoreHeaders(ctx core.HandlerContext)
	ErrorBody(errCode string) map[string]any
}
