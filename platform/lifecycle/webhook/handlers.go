package webhook

import (
	"errors"
	"net/http"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
)

// HandlerDeps is what the webhook admin HTTP handlers need. *sso.Server
// satisfies this via its WebhookEngine() accessor plus the pre-existing
// Auditor() accessor (already required by several other domain handlers).
type HandlerDeps interface {
	WebhookEngine() *Engine
	Auditor() *audit.Recorder
}

// subscriptionRequest is the JSON body for POST /admin/webhooks/subscriptions.
// Secret is REQUIRED — see EventSubscription.Validate.
type subscriptionRequest struct {
	URL         string   `json:"url"`
	EventTypes  []string `json:"event_types"`
	Secret      string   `json:"secret"`
	Description string   `json:"description,omitempty"`
	Disabled    bool     `json:"disabled,omitempty"`
}

func (r subscriptionRequest) toSubscription() EventSubscription {
	types := make([]audit.EventType, 0, len(r.EventTypes))
	for _, t := range r.EventTypes {
		types = append(types, audit.EventType(t))
	}
	return EventSubscription{
		URL:         r.URL,
		EventTypes:  types,
		Secret:      r.Secret,
		Description: r.Description,
		Disabled:    r.Disabled,
	}
}

// subscriptionView is EventSubscription minus the Secret — the admin read
// API NEVER returns secret material (mirrors the credential-rotation /
// crypto-inventory governance endpoints elsewhere in the SDK).
type subscriptionView struct {
	ID          string            `json:"id"`
	URL         string            `json:"url"`
	EventTypes  []audit.EventType `json:"event_types"`
	Description string            `json:"description,omitempty"`
	Disabled    bool              `json:"disabled"`
	HasSecret   bool              `json:"has_secret"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at,omitzero"`
}

func toView(s EventSubscription) subscriptionView {
	return subscriptionView{
		ID:          s.ID,
		URL:         s.URL,
		EventTypes:  s.EventTypes,
		Description: s.Description,
		Disabled:    s.Disabled,
		HasSecret:   s.Secret != "",
		CreatedAt:   s.CreatedAt,
		UpdatedAt:   s.UpdatedAt,
	}
}

// HandleListSubscriptions implements GET /api/v1/admin/webhooks/subscriptions.
func HandleListSubscriptions(d HandlerDeps, ctx core.HandlerContext) {
	subs, ok := subscriptionStoreOrErr(d, ctx)
	if !ok {
		return
	}
	list, err := subs.List(ctx.Request().Context())
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errBody(core.ErrInternal))
		return
	}
	views := make([]subscriptionView, 0, len(list))
	for _, s := range list {
		views = append(views, toView(s))
	}
	ctx.JSON(http.StatusOK, map[string]any{core.KeyWebhookSubscriptions: views})
}

// HandleCreateSubscription implements POST /api/v1/admin/webhooks/subscriptions.
func HandleCreateSubscription(d HandlerDeps, ctx core.HandlerContext) {
	subs, ok := subscriptionStoreOrErr(d, ctx)
	if !ok {
		return
	}
	var req subscriptionRequest
	if err := ctx.Bind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errBodyDesc(core.ErrInvalidRequest, err.Error()))
		return
	}
	sub := req.toSubscription()
	if verr := sub.Validate(); verr != nil {
		ctx.JSON(http.StatusBadRequest, errBodyDesc(core.ErrInvalidRequest, verr.Error()))
		return
	}
	created, err := subs.Create(ctx.Request().Context(), sub)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errBody(core.ErrInternal))
		return
	}
	recordSubscriptionAudit(d, ctx, audit.EventAdminWebhookSubscriptionCreated, created.ID)
	ctx.JSON(http.StatusCreated, map[string]any{core.KeyWebhookSubscription: toView(created)})
}

// HandleDeleteSubscription implements DELETE
// /api/v1/admin/webhooks/subscriptions/:id.
func HandleDeleteSubscription(d HandlerDeps, ctx core.HandlerContext) {
	subs, ok := subscriptionStoreOrErr(d, ctx)
	if !ok {
		return
	}
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, errBody(core.ErrInvalidRequest))
		return
	}
	if err := subs.Delete(ctx.Request().Context(), id); err != nil {
		ctx.JSON(http.StatusInternalServerError, errBody(core.ErrInternal))
		return
	}
	recordSubscriptionAudit(d, ctx, audit.EventAdminWebhookSubscriptionDeleted, id)
	ctx.JSON(http.StatusOK, map[string]string{core.KeyStatus: core.StatusOK})
}

// HandleListDeadLetters implements GET /api/v1/admin/webhooks/deadletters
// (optional ?subscription_id= filter).
func HandleListDeadLetters(d HandlerDeps, ctx core.HandlerContext) {
	eng := d.WebhookEngine()
	if eng == nil || eng.DeadLetters() == nil {
		ctx.JSON(http.StatusInternalServerError, errBody(core.ErrWebhookNotConfigured))
		return
	}
	entries, err := eng.DeadLetters().List(ctx.Request().Context(), DeadLetterFilter{
		SubscriptionID: ctx.Query("subscription_id"),
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{core.KeyWebhookDeadLetters: entries})
}

// HandleReplayDeadLetter implements POST
// /api/v1/admin/webhooks/deadletters/:id/replay.
func HandleReplayDeadLetter(d HandlerDeps, ctx core.HandlerContext) {
	eng := d.WebhookEngine()
	if eng == nil || eng.DeadLetters() == nil {
		ctx.JSON(http.StatusInternalServerError, errBody(core.ErrWebhookNotConfigured))
		return
	}
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, errBody(core.ErrInvalidRequest))
		return
	}
	entry, err := eng.Replay(ctx.Request().Context(), id)
	if errors.Is(err, ErrDeadLetterNotFound) {
		ctx.JSON(http.StatusNotFound, errBody(core.ErrWebhookDeadLetterNotFound))
		return
	}
	if err != nil {
		// The subscription resolve or the replay POST itself failed — an
		// external/upstream condition, not this server's fault; the entry
		// stays queued (possibly with updated Attempts/LastError) for a
		// later retry.
		ctx.JSON(http.StatusBadGateway, errBodyDesc(core.ErrInternal, err.Error()))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{core.KeyWebhookDeadLetter: entry})
}

// subscriptionStoreOrErr resolves the wired SubscriptionStore, writing the
// standard not-configured error and returning ok=false when the feature
// isn't wired (defensive: the routes are only mounted when an Engine IS
// wired, but the check keeps handlers safe if called directly, e.g. tests).
func subscriptionStoreOrErr(d HandlerDeps, ctx core.HandlerContext) (SubscriptionStore, bool) {
	eng := d.WebhookEngine()
	if eng == nil || eng.Subscriptions() == nil {
		ctx.JSON(http.StatusInternalServerError, errBody(core.ErrWebhookNotConfigured))
		return nil, false
	}
	return eng.Subscriptions(), true
}

// recordSubscriptionAudit records an admin-mutation audit event for a
// subscription create/delete, mirroring platform/netpolicy's recordMutation
// helper. No-op when no Recorder is wired.
func recordSubscriptionAudit(d HandlerDeps, ctx core.HandlerContext, t audit.EventType, subscriptionID string) {
	rec := d.Auditor()
	if rec == nil {
		return
	}
	r := ctx.Request()
	rec.Record(r.Context(), &audit.Event{
		Type:      t,
		Outcome:   audit.OutcomeSuccess,
		Timestamp: time.Now().UTC(),
		ActorIP:   r.RemoteAddr,
		UserAgent: r.UserAgent(),
		Reason:    "subscription_id=" + subscriptionID,
	})
}

func errBody(code string) map[string]string { return map[string]string{core.KeyError: code} }

func errBodyDesc(code, desc string) map[string]string {
	return map[string]string{core.KeyError: code, core.KeyErrorDescription: desc}
}
