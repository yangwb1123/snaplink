package compliance

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// ActiveConsentsReporter lists every currently-active (granted, non-expired)
// OAuth consent grant across the system, using ONLY the existing
// core.ConsentStore (per-user ListByUser — there is no "list all" SPI) plus
// core.UserProvider's roster to enumerate subjects: the same composition
// Eraser already uses to walk a subject's data across stores. Revocation is a
// hard delete in every ConsentStore backend, so ListByUser never returns a
// revoked grant — only expiry needs filtering here.
type ActiveConsentsReporter struct {
	Users   core.UserProvider
	Consent core.ConsentStore
}

// ConsentEntry is one active grant, flattened for the report — no fields
// beyond what core.ConsentGrant already records.
type ConsentEntry struct {
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id"`
	Scopes    []string  `json:"scopes"`
	GrantedAt time.Time `json:"granted_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// ActiveConsentsReport is the assembled listing.
type ActiveConsentsReport struct {
	GeneratedAt time.Time      `json:"generated_at"`
	Consents    []ConsentEntry `json:"consents"`
	Total       int            `json:"total"`
	// Errors collects per-user ListByUser failures; one user's failure does
	// not abort the rest of the roster (best-effort, matching Eraser/Exporter).
	Errors []string `json:"errors,omitempty"`
}

// Generate walks every user (core.UserProvider.List) and lists their
// non-expired consent grants. Nil Users or Consent yields an empty (not
// nil-erroring) report — "not wired" reads the same as "wired, nothing
// found" for this report, since there's nothing destructive at stake.
func (r *ActiveConsentsReporter) Generate(ctx context.Context) (*ActiveConsentsReport, error) {
	rep := &ActiveConsentsReport{GeneratedAt: time.Now().UTC(), Consents: []ConsentEntry{}}
	if r.Users == nil || r.Consent == nil {
		return rep, nil
	}
	users, err := r.Users.List(ctx)
	if err != nil {
		return rep, err
	}
	for _, u := range users {
		r.collectUserConsents(ctx, u, rep)
	}
	rep.Total = len(rep.Consents)
	return rep, nil
}

// collectUserConsents lists one user's grants and appends the non-expired
// ones to rep.Consents. A failing user is recorded in rep.Errors and skipped.
func (r *ActiveConsentsReporter) collectUserConsents(ctx context.Context, u *core.User, rep *ActiveConsentsReport) {
	if u == nil || u.ID == "" {
		return
	}
	grants, err := r.Consent.ListByUser(ctx, u.ID)
	if err != nil {
		rep.Errors = append(rep.Errors, fmt.Sprintf("list consent (user=%s): %v", u.ID, err))
		return
	}
	for _, g := range grants {
		if g.IsExpired() {
			continue
		}
		rep.Consents = append(rep.Consents, ConsentEntry{
			UserID:    g.UserID,
			ClientID:  g.ClientID,
			Scopes:    g.Scopes,
			GrantedAt: g.GrantedAt,
			ExpiresAt: g.ExpiresAt,
		})
	}
}

// HandleAdminActiveConsents serves GET /api/v1/admin/compliance/consents —
// every currently-active OAuth consent grant system-wide. admin:read.
func HandleAdminActiveConsents(r *ActiveConsentsReporter, log spi.Logger, ctx core.HandlerContext) {
	rep, err := r.Generate(ctx.Request().Context())
	if err != nil {
		log.Error("active consents report failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, rep)
}
