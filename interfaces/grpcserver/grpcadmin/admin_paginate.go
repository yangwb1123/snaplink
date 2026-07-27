package grpcadmin

import (
	"context"
	"encoding/base64"
	"strconv"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// defaultAdminPageSize/maxAdminPageSize bound every List RPC in this package
// (ClientAdmin, UserAdmin, TenantAdmin, PermissionAdmin, TokenAdmin,
// SnapshotAdmin, ReleaseAdmin). This shim paginates AFTER a full
// store.List(ctx) — it bounds the gRPC RESPONSE, not the store-side
// materialization, so a >10K-row store still pays a full in-memory scan per
// page. The correct fix for that is an OPTIONAL store extension type-asserted
// at this layer (mirroring the existing core.TenantScopedClientStore
// precedent: try an efficient path, fall back to List()) — e.g. a future
// core.PaginatedClientStore / core.PaginatedUserProvider. Deferred; out of
// scope here.
const (
	defaultAdminPageSize = 100
	maxAdminPageSize     = 1000
)

// clampPageSize maps a proto page_size (0 = unset) onto [1, maxAdminPageSize].
func clampPageSize(req int32) int {
	if req <= 0 {
		return defaultAdminPageSize
	}
	if req > maxAdminPageSize {
		return maxAdminPageSize
	}
	return int(req)
}

// decodeOffset decodes an opaque page_token into a decimal slice offset. The
// proto treats the token as opaque, so any decode failure — including a
// negative offset, which can only arise from a tampered/foreign token — is
// reported identically as an invalid page_token.
func decodeOffset(token string) (int, error) {
	if token == "" {
		return 0, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return 0, status.Error(codes.InvalidArgument, "invalid page_token")
	}
	off, err := strconv.Atoi(string(raw))
	if err != nil || off < 0 {
		return 0, status.Error(codes.InvalidArgument, "invalid page_token")
	}
	return off, nil
}

// encodeOffset returns the token for the next page, or "" once the caller
// has reached the end of the (filtered) result set.
func encodeOffset(next, total int) string {
	if next >= total {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(next)))
}

// pageBounds clamps offset/size against total, returning a valid [lo, hi)
// slice window. An offset beyond total yields an empty (but still valid)
// window rather than an error — paging past the end is not a client error.
func pageBounds(offset, size, total int) (lo, hi int) {
	if offset > total {
		offset = total
	}
	hi = offset + size
	if hi > total {
		hi = total
	}
	return offset, hi
}

// parseAdminFilter splits the proto's tiny 'field:value' | 'field eq value'
// filter mini-grammar. An empty expr means "match all" (ok=false signals the
// caller to skip filtering, not an error). A non-empty expr that matches
// neither form yields field="" with ok=true — every entity matcher's field
// switch treats an unrecognized field as InvalidArgument, so a malformed
// filter is rejected rather than silently ignored (STRICT: "bad filter
// value" must error, only a genuinely absent filter matches all).
// Deliberately NOT the SCIM RFC 7644 filter grammar (protocols/scim/filter.go)
// — that parser is unexported, HTTP-request-shaped, and far heavier than
// this proto's mini-grammar warrants; importing protocols/scim here would
// add coupling for no benefit.
func parseAdminFilter(expr string) (field, value string, ok bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return "", "", false
	}
	if idx := strings.Index(expr, ":"); idx >= 0 {
		return strings.TrimSpace(expr[:idx]), strings.TrimSpace(expr[idx+1:]), true
	}
	if parts := strings.SplitN(expr, " eq ", 2); len(parts) == 2 {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
	}
	return "", expr, true
}

// parseOrderBy strips a leading '-' (descending) from an order_by field.
func parseOrderBy(s string) (field string, desc bool) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "-") {
		return strings.TrimSpace(s[1:]), true
	}
	return s, false
}

// recordAdmin / recordAdminMeta below were formerly admin_shared.go, folded
// in here (rather than kept as an 11th file) to stay at the directory's
// 10-file maintainability cap (directory_fanout_test.go) once ListTenants'
// filter/sort support and the split-out admin_domains.go needed a slot.
// Both this file and the audit helpers below are cross-cutting infra used by
// every *AdminService in the package, unlike the other files here which each
// own one service's CRUD — that shared-infra nature is what makes the pairing
// cohesive rather than arbitrary.

// recordAdmin writes one audit event with the ActorID + IP + UA derived from
// the gRPC context. The admin interceptor in the sso package stashes the
// actor's userID + clientID via sso.AdminActorFromContext; we read it back
// here. Safe to call with a nil recorder — checking saves work.
func recordAdmin(ctx context.Context, recorder *audit.Recorder, t audit.EventType, target string) {
	recordAdminMeta(ctx, recorder, t, target, nil)
}

// recordAdminMeta is recordAdmin's metadata-carrying variant — same
// actor/target/context derivation, plus caller-supplied SetMeta entries for
// events needing more than the generic "target=<resource>" Reason (e.g. the
// client-registration review workflow's rejection reason and the rejected
// client's name, captured here since the record is gone after Delete).
func recordAdminMeta(ctx context.Context, recorder *audit.Recorder, t audit.EventType, target string, meta map[string]string) {
	if recorder == nil {
		return
	}
	evt := &audit.Event{
		Type:      t,
		Outcome:   audit.OutcomeSuccess,
		Timestamp: time.Now().UTC(),
		Reason:    "target=" + target,
	}
	if userID, clientID, ok := sso.AdminActorFromContext(ctx); ok {
		evt.ActorID = userID
		evt.ClientID = clientID
	}
	if p, ok := peer.FromContext(ctx); ok && p != nil {
		evt.ActorIP = p.Addr.String()
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if ua := md.Get("user-agent"); len(ua) > 0 {
			evt.UserAgent = ua[0]
		}
	}
	for k, v := range meta {
		audit.SetMeta(evt, k, v)
	}
	recorder.Record(ctx, evt)
}
