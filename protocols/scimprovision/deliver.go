package scimprovision

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/webhook"
	"github.com/yangwb1123/snaplink/protocols/scim"
	"github.com/yangwb1123/snaplink/shared/core"
)

// Known audit-metadata/Reason conventions carrying an event's subject id.
// Different emission sites picked different conventions before this Sink
// existed (protocols/scim's own receiver: Metadata["subject"];
// interfaces/admin + domains/userlifecycle: Metadata["target_user"];
// interfaces/grpcserver/grpcadmin: Reason "target=<id>", occasionally
// "<client_id>/<id>") — rather than a cross-cutting refactor of every
// existing emission site (out of scope), this Sink tries each in turn.
const (
	metaKeySubject     = "subject"
	metaKeyTargetUser  = "target_user"
	reasonTargetPrefix = "target="
)

// subjectID extracts an event's subject id from whichever convention its
// emitter used. "" means no known convention matched — the caller skips.
func subjectID(ev audit.Event) string {
	if v := ev.Metadata[metaKeySubject]; v != "" {
		return v
	}
	if v := ev.Metadata[metaKeyTargetUser]; v != "" {
		return v
	}
	if id, ok := strings.CutPrefix(ev.Reason, reasonTargetPrefix); ok {
		return id
	}
	return ""
}

// groupSubject extracts a group/role event's (clientID, roleCode) pair.
// clientID is "" when the emitter's convention didn't carry one (the SCIM
// receiver's own Metadata["subject"] is a bare role code); the caller then
// trusts the Sink's configured groupClientID scope. ok=false means no known
// convention matched.
func groupSubject(ev audit.Event) (clientID, roleCode string, ok bool) {
	if v := ev.Metadata[metaKeySubject]; v != "" {
		return "", v, true
	}
	if id, cut := strings.CutPrefix(ev.Reason, reasonTargetPrefix); cut {
		if idx := strings.LastIndex(id, "/"); idx >= 0 {
			return id[:idx], id[idx+1:], true
		}
		return "", id, true
	}
	return "", "", false
}

// deliver runs deliverOnce under a RetryingSink (reusing
// platform/audit/auditsink's retry/backoff primitive UNCHANGED, the same
// one platform/lifecycle/webhook.Engine wraps its own per-subscription
// delivery in), then records the terminal outcome. Runs in its own
// goroutine (see Sink.Record); a panic in the provisioner/UserProvider path
// is contained here rather than crashing the process, mirroring
// webhook.Engine.deliver.
func (s *Sink) deliver(ev audit.Event) {
	defer s.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			s.fail(ev, fmt.Sprintf("panic: %v", r))
		}
	}()
	retrying := audit.NewRetryingSink(deliveryFunc(s.deliverOnce),
		audit.WithRetryMaxAttempts(s.retryMaxAttempts),
		audit.WithRetryInitialBackoff(s.retryInitialBackoff),
		audit.WithRetryMaxBackoff(s.retryMaxBackoff),
	)
	if err := retrying.Record(s.ctx, &ev); err != nil {
		s.fail(ev, err.Error())
		return
	}
	if s.metric != nil {
		s.metric(OutcomeDelivered)
	}
}

// deliveryFunc adapts a plain Record-shaped function to auditspi.Sink so
// audit.NewRetryingSink can wrap it — the read paths are never called
// (RetryingSink.Record is the only method the retry loop invokes) but must
// exist to satisfy the interface.
type deliveryFunc func(ctx context.Context, ev *audit.Event) error

func (f deliveryFunc) Record(ctx context.Context, ev *audit.Event) error { return f(ctx, ev) }
func (f deliveryFunc) Get(context.Context, string) (*audit.Event, error) {
	return nil, audit.ErrSinkWriteOnly
}
func (f deliveryFunc) Query(context.Context, audit.Query) ([]*audit.Event, error) {
	return nil, audit.ErrSinkWriteOnly
}

// deliverOnce translates ev into ONE SCIM push and executes it. Re-reads
// current state from the UserProvider/permissions.Provider on every call
// (including retries) rather than snapshotting at Record time — the "resolve
// fresh" discipline CAEP and the webhook engine also follow, so a retry after
// a transient failure reflects the LATEST state, not a stale one.
func (s *Sink) deliverOnce(ctx context.Context, ev *audit.Event) error {
	switch ev.Type {
	case audit.EventAdminUserCreated, audit.EventAdminUserUpdated,
		audit.EventAdminUserEmailChanged, audit.EventAdminUserLifecycleChanged:
		return s.deliverUserUpsert(ctx, *ev)
	case audit.EventAdminUserDeleted:
		return s.deliverUserDelete(ctx, *ev)
	case audit.EventAdminRoleAdded, audit.EventAdminRoleUpdated:
		return s.deliverGroupUpsert(ctx, *ev)
	case audit.EventAdminRoleRemoved:
		return s.deliverGroupDelete(ctx, *ev)
	default:
		return nil // outside our vocabulary; Record already filtered, defensive only
	}
}

// deliverUserUpsert resolves ev's subject against the UserProvider and
// pushes it via ReplaceUser (which itself self-heals to CreateUser downstream
// — see SCIMProvisioner.ReplaceUser). A subject that no longer exists (raced
// with a later delete) is a silent no-op, not an error: there is nothing left
// to push. A transient GetByID failure (store unavailable) is NOT the same
// thing and must propagate so the caller's RetryingSink retries and, on
// exhaustion, dead-letters it — collapsing the two into one no-op would
// silently drop the push instead — mirrors protocols/caep/revoker.go's
// resolveResult distinguishing "definitively absent" from "store
// unavailable" via the same core.ErrNoSuchUser sentinel.
func (s *Sink) deliverUserUpsert(ctx context.Context, ev audit.Event) error {
	id := subjectID(ev)
	if id == "" || s.users == nil {
		return nil
	}
	u, err := s.users.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, core.ErrNoSuchUser) {
			return nil
		}
		return err
	}
	if u == nil {
		return nil
	}
	res := scim.UserToResource(u, "")
	res.ExternalID = u.ID
	// A user provisioned entirely through the admin API (never through the
	// SCIM receiver) has no "scim:userName" attribute, so UserToResource
	// leaves UserName empty — but userName is commonly a REQUIRED
	// identifying attribute downstream (this server's own receiver
	// enforces it too, handler_users.go). Fall back to the one other
	// stable identifier every core.User carries.
	if res.UserName == "" {
		if u.Email != "" {
			res.UserName = u.Email
		} else {
			res.UserName = u.ID
		}
	}
	_, err = s.provisioner.ReplaceUser(ctx, res)
	return err
}

// deliverUserDelete pushes a DeleteUser for ev's subject. No fetch is
// possible (the user is already gone from the UserProvider by the time this
// runs); DeleteUser's own 404-is-success contract makes this idempotent.
func (s *Sink) deliverUserDelete(ctx context.Context, ev audit.Event) error {
	id := subjectID(ev)
	if id == "" {
		return nil
	}
	return s.provisioner.DeleteUser(ctx, id)
}

// deliverGroupUpsert resolves ev's (clientID, roleCode), skips events
// scoped to a DIFFERENT client than this Sink's configured groupClientID
// (never leak another app's role fleet downstream), then pushes the role's
// CURRENT full membership (see doc.go's "full-state reconciliation" note).
func (s *Sink) deliverGroupUpsert(ctx context.Context, ev audit.Event) error {
	role, ok, err := s.resolveGroupSubject(ctx, ev)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	members, err := scim.RoleMembers(ctx, s.perms, s.groupClientID, role.Code)
	if err != nil {
		return err
	}
	g := scim.RoleToGroup(role, members, "")
	g.ExternalID = role.Code
	_, err = s.provisioner.ReplaceGroupMembers(ctx, g)
	return err
}

// deliverGroupDelete pushes a DeleteGroup for ev's role code, after the same
// clientID-scope check deliverGroupUpsert applies (using the raw code — no
// role lookup is needed or possible once it's already removed locally).
func (s *Sink) deliverGroupDelete(ctx context.Context, ev audit.Event) error {
	clientID, roleCode, ok := groupSubject(ev)
	if !ok || roleCode == "" {
		return nil
	}
	if clientID != "" && clientID != s.groupClientID {
		return nil
	}
	if s.perms == nil {
		return nil
	}
	return s.provisioner.DeleteGroup(ctx, roleCode)
}

// resolveGroupSubject applies the clientID-scope check and looks up the
// CURRENT role definition. ok=false with a nil err signals a legitimate
// "skip": an out-of-scope event, an unmatched event convention, or a role
// that no longer exists (raced with a later removal). A non-nil err is a
// genuine backend failure resolving the role (e.g. the permissions.Provider
// is unavailable) and must propagate rather than be folded into "skip" —
// otherwise deliverGroupUpsert would silently drop the push instead of
// letting its RetryingSink retry/dead-letter it, the same distinction
// protocols/caep/revoker.go's resolveResult draws for its own lookup.
func (s *Sink) resolveGroupSubject(ctx context.Context, ev audit.Event) (role permissions.Role, ok bool, err error) {
	if s.perms == nil {
		return permissions.Role{}, false, nil
	}
	clientID, roleCode, found := groupSubject(ev)
	if !found || roleCode == "" {
		return permissions.Role{}, false, nil
	}
	if clientID != "" && clientID != s.groupClientID {
		return permissions.Role{}, false, nil
	}
	role, exists, err := scim.FindRoleByCode(ctx, s.perms, s.groupClientID, roleCode)
	if err != nil {
		return permissions.Role{}, false, err
	}
	if !exists {
		return permissions.Role{}, false, nil
	}
	return role, true, nil
}

// fail records a delivery's exhausted-retry outcome: metric, log, an
// EventSCIMProvisionFailed audit event (best-effort, when a failure recorder
// is wired), and — the durable piece — a webhook.DeadLetterEntry so an
// operator can inspect the failure later (reusing the generic webhook
// engine's dead-letter storage rather than a parallel type).
func (s *Sink) fail(ev audit.Event, reason string) {
	if s.metric != nil {
		s.metric(OutcomeFailed)
	}
	if s.logger != nil {
		s.logger.Error("scimprovision: delivery failed", "event_type", string(ev.Type), "reason", reason)
	}
	now := time.Now().UTC()
	if s.dlq != nil {
		if s.metric != nil {
			s.metric(OutcomeDeadLettered)
		}
		_, _ = s.dlq.Add(context.Background(), webhook.DeadLetterEntry{
			SubscriptionID: "scim-push",
			URL:            "",
			Event:          ev,
			Attempts:       s.retryMaxAttempts,
			LastError:      reason,
			FirstFailedAt:  now,
			LastFailedAt:   now,
		})
	}
	if s.recorder != nil {
		fe := &audit.Event{
			Type:      EventSCIMProvisionFailed,
			Outcome:   audit.OutcomeFailure,
			Timestamp: now,
			Reason:    reason,
		}
		audit.SetMeta(fe, "source_event_type", string(ev.Type))
		s.recorder.Record(context.Background(), fe)
	}
}

// Replay re-attempts delivery of a dead-lettered event — a single attempt,
// no retry chain (an explicit synchronous admin action gets an immediate
// result rather than waiting out a multi-attempt backoff), re-resolving
// current UserProvider/permissions.Provider state exactly like a fresh
// delivery. Mirrors webhook.Engine.Replay's shape and "resolve fresh"
// philosophy.
func (s *Sink) Replay(ctx context.Context, id string) (webhook.DeadLetterEntry, error) {
	if s == nil || s.dlq == nil {
		return webhook.DeadLetterEntry{}, webhook.ErrDeadLetterNotFound
	}
	entry, err := s.dlq.Get(ctx, id)
	if err != nil {
		return webhook.DeadLetterEntry{}, err
	}
	evCopy := entry.Event
	if sendErr := s.deliverOnce(ctx, &evCopy); sendErr != nil {
		entry.Attempts++
		entry.LastError = sendErr.Error()
		entry.LastFailedAt = time.Now().UTC()
		_, _ = s.dlq.Add(ctx, entry)
		return entry, sendErr
	}
	_ = s.dlq.Delete(ctx, id)
	return entry, nil
}
