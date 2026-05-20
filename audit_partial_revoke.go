package sso

import (
	"strings"
	"time"

	"github.com/snaplink/sso/audit"
)

// auditPartialRevokeFailure emits an `EventPartialRevokeFailure` event
// when at least one TokenIssuer failed to revoke a token while at
// least one succeeded — the "logout everywhere" promise has been
// partially violated and operators MUST follow up manually before the
// failed-issuer's tokens reach natural expiry.
//
// Both lists are recorded so SIEM filters can compute the success
// ratio over time and alert when failed/(revoked+failed) crosses a
// threshold. When failed is empty (full success or "no issuer owned
// this token"), this is a no-op — emitting an event in those cases
// would be noise.
//
// Safe to call with a nil Recorder (matches the rest of the audit
// surface). Uses setMeta so geo + tenant middleware enrichment isn't
// clobbered.
func (s *Server) auditPartialRevokeFailure(ctx HandlerContext, revoked, failed []string) {
	if s.auditor == nil || len(failed) == 0 {
		return
	}
	e := &audit.Event{
		Type:      audit.EventPartialRevokeFailure,
		Outcome:   audit.OutcomeFailure,
		Timestamp: time.Now(),
	}
	setMeta(e, "revoked", strings.Join(revoked, ","))
	setMeta(e, "failed", strings.Join(failed, ","))
	s.auditor.Record(ctx.Request().Context(), e)
}
