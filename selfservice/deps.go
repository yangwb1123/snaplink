package selfservice

import (
	"context"
	"fmt"
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/compliance"
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

	// Bearer validation for authenticated /me endpoints.
	MeSubjectOrChallenge(ctx core.HandlerContext) (userID string, ok bool)

	// GDPR self-service
	DataExporter() *compliance.Exporter
	AccountEraser() *compliance.Eraser
}

// RecordSelfErase emits a subject_self_erased audit event for GDPR Art. 17
// self-service erasure. No-op when no auditor is wired.
func RecordSelfErase(d Deps, ctx core.HandlerContext, userID string, report *compliance.Report) {
	aud := d.Auditor()
	if aud == nil {
		return
	}
	evt := &audit.Event{
		Type:    audit.EventSubjectSelfErased,
		Outcome: audit.OutcomeSuccess,
		ActorID: userID,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, "dry_run", fmt.Sprintf("%t", report.DryRun))
	audit.SetMeta(evt, "sessions_destroyed", fmt.Sprintf("%d", report.SessionsDestroyed))
	audit.SetMeta(evt, "refresh_tokens_deleted", fmt.Sprintf("%d", report.RefreshTokensDeleted))
	audit.SetMeta(evt, "user_deleted", fmt.Sprintf("%t", report.UserDeleted))
	if err := report.Err(); err != nil {
		evt.Outcome = audit.OutcomeFailure
		evt.Reason = err.Error()
	}
	aud.Record(ctx.Request().Context(), evt)
}
