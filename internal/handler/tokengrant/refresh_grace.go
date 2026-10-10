package tokengrant

import (
	"maps"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

const (
	refreshGraceGrantDeadline = core.KeyRefreshGraceDeadline
	refreshGracePendingWait   = 250 * time.Millisecond
	refreshGracePendingPoll   = 10 * time.Millisecond
)

// refreshGraceCache makes a benign concurrent double-submit of a refresh token
// idempotent. When a token is rotated, its successor response is cached for a
// short window keyed by the CONSUMED token; a near-simultaneous second
// presentation of the SAME token (a multi-tab SPA, a mobile cold-start race, or
// an HTTP retry after a dropped 200) then replays that SAME successor instead
// of tripping refresh-token-family reuse detection and killing the whole family
// — the "double-submit logout storm" false-positive.
//
// This does NOT weaken BCP §4.13 reuse detection: the grace only ever returns
// the ALREADY-ISSUED successor for the immediately-prior token within the
// window. A genuine post-window replay (or any token never cached here) finds
// no entry and falls through to the family-reuse kill exactly as before. The
// cached response is held at most `window` and the map is pruned lazily on each
// access, so it stays bounded by rotation-rate × window.
type RefreshGraceCache struct {
	window time.Duration
	mu     sync.Mutex
	m      map[string]refreshGraceEntry
}

type refreshGraceEntry struct {
	resp    map[string]any
	expires time.Time
}

func NewRefreshGraceCache(window time.Duration) *RefreshGraceCache {
	return &RefreshGraceCache{window: window, m: make(map[string]refreshGraceEntry)}
}

// MTLSCertNotAfterFrom reads the request-scoped mTLS certificate expiry. A
// missing or incorrectly typed value is deliberately treated as uncapped.
func MTLSCertNotAfterFrom(ctx core.HandlerContext) time.Time {
	if ctx == nil {
		return time.Time{}
	}
	notAfter, _ := ctx.Get(core.MTLSCertNotAfterContextKey).(time.Time)
	return notAfter
}

// remember caches resp as the successor for the just-consumed token. resp is
// cloned so a later caller mutation can't corrupt the cached copy.
func (c *RefreshGraceCache) Remember(token string, resp map[string]any, now time.Time) {
	if c == nil || token == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	expiresAt := core.RefreshGraceExpiresAt(resp, now, c.window)
	if !now.Before(expiresAt) {
		return
	}
	c.m[token] = refreshGraceEntry{resp: maps.Clone(resp), expires: expiresAt}
}

// PreparePending never overwrites a live pending or completed response.
func (c *RefreshGraceCache) PreparePending(token string, resp map[string]any, now time.Time) {
	if c == nil || token == "" {
		return
	}
	body := core.RefreshGracePendingResponse(resp, now, c.window)
	if body == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	if _, exists := c.m[token]; !exists {
		c.m[token] = refreshGraceEntry{resp: body, expires: core.RefreshGraceExpiresAt(body, now, c.window)}
	}
}

// lookup returns a COPY of the cached successor response for token if it was
// rotated within the grace window (else nil,false). Expired-at-exactly-now is
// treated as expired.
func (c *RefreshGraceCache) Lookup(token string, now time.Time) (map[string]any, bool) {
	if c == nil || token == "" {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[token]
	if !ok || !now.Before(e.expires) {
		return nil, false
	}
	return maps.Clone(e.resp), true
}

// pruneLocked drops every expired entry. Caller holds c.mu.
func (c *RefreshGraceCache) pruneLocked(now time.Time) {
	for k, e := range c.m {
		if !now.Before(e.expires) {
			delete(c.m, k)
		}
	}
}

// RefreshGraceStore is the pluggable backend for the double-submit grace window.
// *RefreshGraceCache is the in-process (single-replica) impl; a Redis-backed
// impl with the SAME method set makes the decision CLUSTER-SHARED, so a
// double-submit landing on a different replica than the rotation still replays
// the successor instead of tripping a false family-reuse kill (the logout storm
// on every multi-replica deployment). Lookup MUST return false on ANY
// uncertainty (miss / expiry / backend error) so the caller fails closed to
// family-reuse detection — BCP 4.13 is never weakened.
type RefreshGraceStore interface {
	Remember(token string, resp map[string]any, now time.Time)
	Lookup(token string, now time.Time) (map[string]any, bool)
}

// RefreshGracePendingStore is additive; old custom stores retain completed-
// response replay but cannot protect the consume-to-publication interval.
type RefreshGracePendingStore interface {
	PreparePending(token string, resp map[string]any, now time.Time)
}

func prepareRefreshGrace(d RefreshGrantDeps, ctx core.HandlerContext, client *core.Client, token, dpopJKT, mtlsX5T string) {
	pending, ok := d.RefreshGrace().(RefreshGracePendingStore)
	inspector, canInspect := d.RefreshTokenStore().(oauth.RefreshTokenInspector)
	if !ok || !canInspect {
		return
	}
	info, err := inspector.Inspect(ctx.Request().Context(), token)
	if err != nil || info == nil || info.IsExpired() || info.FamilyID == "" || info.ClientID != client.ID || (info.ConfirmationJKT != "" && info.ConfirmationJKT != dpopJKT) {
		return
	}
	pending.PreparePending(token, map[string]any{
		core.KeyRefreshGracePending: true, core.KeyRefreshGraceFamilyID: info.FamilyID,
		core.KeyRefreshGraceClientID: client.ID, core.KeyRefreshGraceJKT: dpopJKT,
		core.KeyRefreshGraceX5T: mtlsX5T, refreshGraceGrantDeadline: info.ExpiresAt.Format(time.RFC3339Nano),
	}, time.Now())
}

// A pending marker suppresses family revocation, never grant validation or
// issuance. On a bounded incomplete response the wire stays invalid_grant.
func awaitPendingRefreshGrace(d RefreshGrantDeps, ctx core.HandlerContext, client *core.Client, token, familyID, dpopJKT, mtlsX5T string, replay func() bool) bool {
	grace := d.RefreshGrace()
	if grace == nil {
		return false
	}
	limit := time.NewTimer(refreshGracePendingWait)
	poll := time.NewTicker(refreshGracePendingPoll)
	defer limit.Stop()
	defer poll.Stop()
	for {
		cached, hit := grace.Lookup(token, time.Now())
		if !hit || !matchingPendingRefreshGrace(cached, client.ID, familyID, dpopJKT, mtlsX5T) {
			return replay()
		}
		select {
		case <-ctx.Request().Context().Done():
		case <-limit.C:
		case <-poll.C:
			continue
		}
		// Never suppress reuse from evidence that expired during the wait.
		cached, hit = grace.Lookup(token, time.Now())
		if !hit || !matchingPendingRefreshGrace(cached, client.ID, familyID, dpopJKT, mtlsX5T) {
			return replay()
		}
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return true
	}
}

func matchingPendingRefreshGrace(cached map[string]any, clientID, familyID, dpopJKT, mtlsX5T string) bool {
	deadline, _ := cached[refreshGraceGrantDeadline].(string)
	expiresAt, err := time.Parse(time.RFC3339Nano, deadline)
	return err == nil && time.Now().Before(expiresAt) && familyID != "" &&
		cached[core.KeyRefreshGracePending] == true && cached[core.KeyRefreshGraceFamilyID] == familyID &&
		cached[core.KeyRefreshGraceClientID] == clientID && cached[core.KeyRefreshGraceJKT] == dpopJKT && cached[core.KeyRefreshGraceX5T] == mtlsX5T
}

// Keep the original grant and access-token deadlines out of the wire body.
// Old entries without deadline evidence are deliberately not replayable.
func rememberRefreshGrace(grace RefreshGraceStore, token string, resp map[string]any, expiresAt time.Time, accessTTL time.Duration) {
	now := time.Now()
	if expiresAt.IsZero() || !now.Before(expiresAt) || accessTTL <= 0 {
		return
	}
	if accessDeadline := now.Add(accessTTL); accessDeadline.Before(expiresAt) {
		expiresAt = accessDeadline
	}
	cached := make(map[string]any, len(resp)+1)
	for key, value := range resp {
		cached[key] = value
	}
	cached[refreshGraceGrantDeadline] = expiresAt.Format(time.RFC3339Nano)
	grace.Remember(token, cached, now)
}

// Replay only the immediate live successor, with fresh client, sender,
// lifecycle, session and scope checks. A cache hit is not authorization.
func replayRefreshGrace(d RefreshGrantDeps, ctx core.HandlerContext, client *core.Client, store oauth.RefreshTokenStore, token, scope, dpopJKT, mtlsX5T, familyID string) bool {
	cached, info := liveRefreshGrace(d.RefreshGrace(), ctx, store, token)
	if info == nil || info.FamilyID != familyID {
		return false
	}
	if info.ClientID != client.ID || (info.ConfirmationJKT != "" && info.ConfirmationJKT != dpopJKT) {
		return false
	}
	if refreshEnforceAbsoluteMaxLifetime(d, ctx, info) || refreshCheckSessionLiveness(d, ctx, info) || lifecycleGrantBlocked(d, ctx, info.UserID) {
		return true
	}
	scopes, handled := refreshResolveGrant(d, ctx, client, info, scope)
	if handled {
		return true
	}
	if cached[core.KeyScope] != strings.Join(scopes, " ") || !refreshGraceAccessValid(d, ctx, client, cached, dpopJKT, mtlsX5T) {
		return false
	}
	for _, key := range []string{refreshGraceGrantDeadline, core.KeyRefreshGracePending, core.KeyRefreshGraceFamilyID, core.KeyRefreshGraceClientID, core.KeyRefreshGraceJKT, core.KeyRefreshGraceX5T} {
		delete(cached, key)
	}
	ctx.JSON(http.StatusOK, cached)
	return true
}

func refreshGraceAccessValid(d RefreshGrantDeps, ctx core.HandlerContext, client *core.Client, cached map[string]any, dpopJKT, mtlsX5T string) bool {
	token, _ := cached[core.KeyAccessToken].(string)
	_, issuer, err := d.IssuerForClient(client)
	if err != nil || token == "" {
		return false
	}
	claims, err := issuer.Validate(ctx.Request().Context(), token)
	return err == nil && claims != nil && claims.ClientID == client.ID && claims.TenantID == client.TenantID && claims.ConfirmationJKT == dpopJKT && claims.ConfirmationX5TS256 == mtlsX5T
}

func liveRefreshGrace(grace RefreshGraceStore, ctx core.HandlerContext, store oauth.RefreshTokenStore, token string) (map[string]any, *oauth.RefreshToken) {
	if grace == nil {
		return nil, nil
	}
	cached, ok := grace.Lookup(token, time.Now())
	if !ok {
		return nil, nil
	}
	deadline, _ := cached[refreshGraceGrantDeadline].(string)
	expiresAt, err := time.Parse(time.RFC3339Nano, deadline)
	if err != nil || !time.Now().Before(expiresAt) {
		return nil, nil
	}
	inspector, ok := store.(oauth.RefreshTokenInspector)
	successor, _ := cached[core.KeyRefreshToken].(string)
	if !ok || successor == "" {
		return nil, nil
	}
	info, err := inspector.Inspect(ctx.Request().Context(), successor)
	if err != nil || info == nil || info.IsExpired() {
		return nil, nil
	}
	return cached, info
}

var _ RefreshGraceStore = (*RefreshGraceCache)(nil)
var _ RefreshGracePendingStore = (*RefreshGraceCache)(nil)
