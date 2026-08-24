package grpcadmin

import (
	"context"
	"encoding/base64"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/domains/tenant"
	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
	"github.com/yangwb1123/snaplink/interfaces/snapshot"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/operations"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
	"github.com/yangwb1123/snaplink/shared/security/clientrotation"
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
	defaultExpiryWindow  = 30 * 24 * time.Hour
	maxClientLifetime    = 100 * 365 * 24 * time.Hour
)

// ListExpiring returns confidential clients with a persisted expiry no later
// than the requested horizon. Legacy/public clients (zero expiry) are omitted.
//
// Extension path (store implements core.ClientExpiryLister): a windowed
// keyset page — the new page params apply even when absent (the window IS
// the page). Decorator ErrUnsupportedOperation means "extension absent" and
// falls back; any other extension error propagates Internal — a broken
// backend must not be masked by a slow full scan.
//
// Fallback path: today's full scan -> window filter -> deterministic sort,
// with the new page params applied as offset pagination over the filtered
// slice when present (absent params = today's return-everything behavior).
func (s *ClientAdminService) ListExpiring(ctx context.Context, in *adminv1.ListExpiringClientsRequest) (*adminv1.ListExpiringClientsResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "client store not configured")
	}
	window, err := expiryWindow(in)
	if err != nil {
		return nil, err
	}
	cutoff := time.Now().Add(window)
	pageSize := clampPageSize(in.GetPageSize())
	if items, next, hint, ok, lerr := listExpiringViaExtension(ctx, s.store, cutoff, pageSize); ok {
		if lerr != nil {
			return nil, status.Errorf(codes.Internal, "list expiring clients: %v", lerr)
		}
		return expiringResponse(items, next, pageHintTotal(hint)), nil
	}
	all, err := s.store.List(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list expiring clients: %v", err)
	}
	windowed, total, nextToken, err := windowExpiring(all, cutoff, in.GetPageToken(), pageSize)
	if err != nil {
		return nil, err
	}
	return expiringResponse(windowed, nextToken, total), nil
}

// listExpiringViaExtension prefers the optional expiry-aware page SPI; a store
// without it reports unsupported and the caller falls back to full List.
func listExpiringViaExtension(ctx context.Context, store core.ClientStore, cutoff time.Time, pageSize int) ([]*sso.Client, string, int, bool, error) {
	ext, ok := store.(core.ClientExpiryLister)
	if !ok {
		return nil, "", 0, false, nil
	}
	items, next, hint, err := ext.ListExpiringPage(ctx, cutoff, core.PageQuery{Limit: pageSize})
	if errors.Is(err, core.ErrUnsupportedOperation) {
		return nil, "", 0, false, nil
	}
	if err != nil {
		return nil, "", 0, true, err
	}
	nextToken, terr := security.DefaultPageCursorCodec().Encode(next, "", "")
	if terr != nil {
		return nil, "", 0, true, terr
	}
	return items, nextToken, hint, true, nil
}

// windowExpiring filters the full list down to the expiry window and applies
// the offset page window when a token or size is requested.
func windowExpiring(all []*sso.Client, cutoff time.Time, token string, pageSize int) ([]*sso.Client, int32, string, error) {
	var expiring []*sso.Client
	for _, client := range all {
		if !client.SecretExpiresAt.IsZero() && !client.SecretExpiresAt.After(cutoff) {
			expiring = append(expiring, client)
		}
	}
	sort.Slice(expiring, func(i, j int) bool {
		if expiring[i].SecretExpiresAt.Equal(expiring[j].SecretExpiresAt) {
			return expiring[i].ID < expiring[j].ID
		}
		return expiring[i].SecretExpiresAt.Before(expiring[j].SecretExpiresAt)
	})
	total := int32(len(expiring))
	windowed := expiring
	nextToken := ""
	if token != "" || pageSize != 0 {
		offset, derr := decodeOffset(token)
		if derr != nil {
			return nil, 0, "", derr
		}
		lo, hi := pageBounds(offset, pageSize, len(expiring))
		windowed = expiring[lo:hi]
		nextToken = encodeOffset(hi, len(expiring))
	}
	return windowed, total, nextToken, nil
}

// expiringResponse projects expiring clients onto the wire response.
func expiringResponse(items []*sso.Client, nextToken string, total int32) *adminv1.ListExpiringClientsResponse {
	out := &adminv1.ListExpiringClientsResponse{
		Clients:       make([]*adminv1.Client, 0, len(items)),
		TotalSize:     total,
		NextPageToken: nextToken,
	}
	for _, client := range items {
		out.Clients = append(out.Clients, clientToProto(client, false))
	}
	return out
}

// pageHintTotal maps a store totalHint onto TotalSize per the D7 sourcing
// rules: -1 ("backend has no cheap count") reports 0 — the proto's
// "Approximate… for UI display" contract treats 0 as an honest unknown
// rather than paying for a full scan. Memory backends return the exact
// count, so every existing TotalSize assertion holds on the extension path.
func pageHintTotal(hint int) int32 {
	if hint >= 0 {
		return int32(hint)
	}
	return 0
}

func expiryWindow(in *adminv1.ListExpiringClientsRequest) (time.Duration, error) {
	if in == nil || in.WithinSeconds == 0 {
		return defaultExpiryWindow, nil
	}
	if in.WithinSeconds < 0 || in.WithinSeconds > int64(maxClientLifetime/time.Second) {
		return 0, status.Error(codes.InvalidArgument, "within_seconds must be between 1 and 100 years")
	}
	return time.Duration(in.WithinSeconds) * time.Second, nil
}

func clientRotationPolicy(in *adminv1.RotateSecretRequest) (time.Duration, time.Duration, error) {
	maxSeconds := int64(maxClientLifetime / time.Second)
	if in.OverlapSeconds < 0 || in.LifetimeSeconds < 0 ||
		in.OverlapSeconds > maxSeconds || in.LifetimeSeconds > maxSeconds {
		return 0, 0, status.Error(codes.InvalidArgument, "rotation durations must be between 0 and 100 years")
	}
	overlap := clientrotation.DefaultOverlap
	if in.OverlapSeconds != 0 {
		overlap = time.Duration(in.OverlapSeconds) * time.Second
	}
	lifetime := clientrotation.DefaultLifetime
	if in.LifetimeSeconds != 0 {
		lifetime = time.Duration(in.LifetimeSeconds) * time.Second
	}
	if overlap < time.Hour || lifetime <= overlap {
		return 0, 0, status.Error(codes.InvalidArgument, "rotation policy requires overlap >= 1h and lifetime > overlap (max 100 years)")
	}
	return overlap, lifetime, nil
}

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

func (l sessionPageLister) ListPage(ctx context.Context, q core.PageQuery) ([]*sso.Session, []byte, int, error) {
	return l.inner.ListPage(ctx, l.userID, q)
}

// domainPageLister adapts the tenantID-scoped tenant.PaginatedDomainStore.
// tenantID "" = every domain (ListDomains); non-empty = that tenant's
// (ListDomainsByTenant).
type domainPageLister struct {
	inner    tenant.PaginatedDomainStore
	tenantID string
}

func (l domainPageLister) ListPage(ctx context.Context, q core.PageQuery) ([]*tenant.Domain, []byte, int, error) {
	return l.inner.ListDomainsPage(ctx, l.tenantID, q)
}

// rolePageLister and assignmentPageLister adapt the clientID-scoped
// permissions.PaginatedPermissionProvider to pageLister for each List RPC.
type rolePageLister struct {
	inner    permissions.PaginatedPermissionProvider
	clientID string
}

func (l rolePageLister) ListPage(ctx context.Context, q core.PageQuery) ([]permissions.Role, []byte, int, error) {
	return l.inner.ListRolesPage(ctx, l.clientID, q)
}

type assignmentPageLister struct {
	inner    permissions.PaginatedPermissionProvider
	clientID string
}

func (l assignmentPageLister) ListPage(ctx context.Context, q core.PageQuery) ([]permissions.Assignment, []byte, int, error) {
	return l.inner.ListAssignmentsPage(ctx, l.clientID, q)
}

// runListPage dispatches one List RPC. When ext is implemented the
// extension path runs (validation -> cursor decode/bind -> store pushdown);
// otherwise the legacy path runs unchanged: listAll -> filterSort -> offset
// decode -> slice. ErrUnsupportedOperation from a decorator passthrough
// (ClientStoreCache) means "extension absent" and falls back silently.
//
// listAll must return ALREADY-WRAPPED errors (each RPC's historical message
// shape, e.g. "list tenants: %v") since the fallback propagates them as-is;
// errPrefix carries the same shape for the extension path's Internal wrap.
// filterSort implements the fallback's filter-then-sort semantics (capturing
// the request's filter); validate is the row-independent spec check used
// ONLY by the extension path — the fallback's own matchers produce the same
// errors in the same order. hintTotal (nil = D7 default) resolves a
// totalHint into TotalSize with access to the concrete store (Stats).
func runListPage[T any](ctx context.Context, token string, pageSize int32, orderBy, filter string,
	ext pageLister[T],
	listAll func(context.Context) ([]T, error),
	filterSort func(items []T, orderBy string) ([]T, error),
	validate func(filter, orderBy string) error,
	errPrefix string,
	hintTotal func(context.Context, int) int32,
) (items []T, nextToken string, total int32, err error) {
	if ext != nil {
		items, nextToken, total, err = runPageExtension(ctx, token, pageSize, orderBy, filter, ext, validate, errPrefix, hintTotal)
		if err == nil || !errors.Is(err, core.ErrUnsupportedOperation) {
			return items, nextToken, total, err
		}
	}
	all, err := listAll(ctx)
	if err != nil {
		// A listAll closure may already have mapped its store error to a gRPC
		// status (e.g. ListSessions maps unsupported -> Unimplemented); pass
		// those through untouched. Bare sentinels map UnsupportedOperation to
		// Unimplemented and everything else to Internal under errPrefix,
		// matching the pre-pagination behavior each List had.
		if status.Code(err) != codes.Unknown {
			return nil, "", 0, err
		}
		if errors.Is(err, core.ErrUnsupportedOperation) {
			return nil, "", 0, status.Error(codes.Unimplemented, err.Error())
		}
		return nil, "", 0, status.Errorf(codes.Internal, errPrefix, err)
	}
	all, err = filterSort(all, orderBy)
	if err != nil {
		return nil, "", 0, err
	}
	offset, err := decodeOffset(token)
	if err != nil {
		return nil, "", 0, err
	}
	lo, hi := pageBounds(offset, clampPageSize(pageSize), len(all))
	return all[lo:hi], encodeOffset(hi, len(all)), int32(len(all)), nil
}

// runPageExtension drives the keyset path: canonicalize + validate the
// filter/order spec, decode + bind the MAC'd cursor token to that spec,
// push the query down to the store, wrap the store's opaque next-cursor in
// a fresh token, and resolve TotalSize. Every cursor failure — wrong shape,
// MAC mismatch, filter/order mismatch — collapses to the byte-identical
// InvalidArgument "invalid page_token" (the same message the offset path
// uses for a negative/tampered offset).
func runPageExtension[T any](ctx context.Context, token string, pageSize int32, orderBy, filter string,
	ext pageLister[T], validate func(filter, orderBy string) error, errPrefix string,
	hintTotal func(context.Context, int) int32,
) (items []T, nextToken string, total int32, err error) {
	filterCanonical := ""
	if field, value, ok := core.ParseFilterExpr(filter); ok {
		filterCanonical = strings.ToLower(field) + ":" + value
	}
	orderField, desc := parseOrderBy(orderBy)
	orderCanonical := strings.ToLower(orderField)
	if desc {
		orderCanonical = "-" + orderCanonical
	}
	if validate != nil {
		if err := validate(filter, orderBy); err != nil {
			return nil, "", 0, err
		}
	}
	var after []byte
	if token != "" {
		tokenAfter, tokenFilter, tokenOrder, derr := security.DefaultPageCursorCodec().Decode(token)
		if derr != nil || tokenFilter != filterCanonical || tokenOrder != orderCanonical {
			return nil, "", 0, status.Error(codes.InvalidArgument, "invalid page_token")
		}
		after = tokenAfter
	}
	page, next, hint, lerr := ext.ListPage(ctx, core.PageQuery{
		Limit: clampPageSize(pageSize), OrderBy: orderField, Desc: desc, Filter: filter, After: after,
	})
	if lerr != nil {
		if errors.Is(lerr, core.ErrUnsupportedOperation) {
			return nil, "", 0, lerr // raw, so runListPage can fall back silently
		}
		return nil, "", 0, status.Errorf(codes.Internal, errPrefix, lerr)
	}
	if len(next) > 0 {
		nextToken, err = security.DefaultPageCursorCodec().Encode(next, filterCanonical, orderCanonical)
		if err != nil {
			return nil, "", 0, status.Errorf(codes.Internal, "%s", err)
		}
	}
	if hintTotal != nil {
		total = hintTotal(ctx, hint)
	} else {
		total = pageHintTotal(hint)
	}
	return page, nextToken, total, nil
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
	recordAdminOutcomeMeta(ctx, recorder, t, target, audit.OutcomeSuccess, meta)
}

// recordAdminFailureMeta preserves sanitized mutation failure context in the
// audit trail without changing the oracle-safe gRPC status returned to callers.
func recordAdminFailureMeta(ctx context.Context, recorder *audit.Recorder, t audit.EventType, target string, meta map[string]string) {
	recordAdminOutcomeMeta(ctx, recorder, t, target, audit.OutcomeFailure, meta)
}

func recordAdminOutcomeMeta(ctx context.Context, recorder *audit.Recorder, t audit.EventType, target string, outcome audit.Outcome, meta map[string]string) {
	if recorder == nil {
		return
	}
	evt := &audit.Event{
		Type:      t,
		Outcome:   outcome,
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

type OperationAdminService struct {
	adminv1.UnimplementedOperationAdminServiceServer
	store operations.Store
}

// snapshotMetas peeks each snapshot's envelope for its header fields. Body
// fields live inside the (potentially encrypted) body and stay zero here; kind
// comes from the envelope HEADER, so it is available without decryption.
func (s *SnapshotAdminService) snapshotMetas(ctx context.Context, names []string) ([]*adminv1.SnapshotMeta, error) {
	out := make([]*adminv1.SnapshotMeta, 0, len(names))
	for _, name := range names {
		raw, err := s.storage.Get(ctx, name)
		if err != nil {
			return nil, mapSnapshotError(err, "get "+name)
		}
		env, err := snapshot.PeekEnvelope(raw)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "peek %s: %v", name, err)
		}
		out = append(out, &adminv1.SnapshotMeta{
			SnapshotId:          env.SnapshotID,
			SchemaVersion:       snapshot.SchemaVersion,
			Codec:               env.Codec,
			EncryptionAlgorithm: env.Algorithm,
			SizeBytes:           int64(len(raw)),
			Kind:                env.Kind,
		})
	}
	return out, nil
}
