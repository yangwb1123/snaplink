package core

import (
	"context"
	"encoding/base64"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// PathJWKS is the standard discovery endpoint for the issuer's signing keys.
const PathJWKS = "/.well-known/jwks.json"

// JWK is a single JSON Web Key entry. Fields follow RFC 7517; only the
// subset relevant to the issuers shipped in this SDK is exposed. Issuers can
// emit additional fields by embedding extra json tags in their own structs.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`

	// OKP (Ed25519): Crv + X
	// EC (P-256/ES256): Crv + X + Y
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`

	// RSA: N + E
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	// Origin is the HSM/software attestation of where this key was
	// generated (see KeyOrigin). Populated only when the TokenIssuer
	// that published this key implements KeyOriginProvider and the
	// origin differs from OriginUnattested. Omitted from JSON when
	// absent (zero value), so JWK consumers that don't understand
	// this field are unaffected.
	Origin KeyOrigin `json:"origin,omitempty,omitzero"`
}

// JWKSProvider is implemented by TokenIssuer types whose tokens are publicly
// verifiable. The Server's JWKS endpoint aggregates JWKs from every
// registered issuer that satisfies this interface; symmetric issuers (HMAC,
// opaque session) simply skip the assertion and are excluded.
type JWKSProvider interface {
	JWKS(ctx context.Context) ([]JWK, error)
}

// DefaultJWKSCacheMaxAge is the freshness window advertised in
// Cache-Control for the JWKS response. 5 minutes balances key-
// rotation responsiveness against avoiding per-request hits from
// heavily-deployed RPs.
//
// Operators who rotate keys faster MUST lower this AND set
// `kid` rotation expectations on RPs — JWKS caches stick around in
// libraries past this timeout in some cases.
const DefaultJWKSCacheMaxAge = 5 * time.Minute

// KeyOrigin classifies where a cryptographic signing key was generated,
// for compliance attestation (FIPS 140-2/3, PCI-DSS, SOC 2). It answers
// the audit question "was this key generated inside an HSM?"
type KeyOrigin int8

const (
	// OriginUnattested is the default — the key was generated in software
	// with no hardware-backed attestation. Every issuer that does not
	// explicitly implement KeyOriginProvider reports this value.
	OriginUnattested KeyOrigin = 0
	// OriginHSMGenerated means the key was generated inside an HSM and
	// the private key material never left the hardware boundary (or, for
	// cloud KMS, was generated within the KMS service's FIPS boundary).
	OriginHSMGenerated KeyOrigin = 1
	// OriginImported means the key was generated outside the HSM (e.g.
	// in software or an on-premises PKI) and then imported into the HSM
	// or KMS service. The private key material was at some point outside
	// the hardware boundary.
	OriginImported KeyOrigin = 2
	// OriginUnknown means the KMS backend or the key's metadata does not
	// support origin attestation. This signals an inability to answer the
	// audit question rather than a verdict.
	OriginUnknown KeyOrigin = 3
)

// String returns a human-readable label for the origin. Used in JWKS
// extension metadata and audit events.
func (o KeyOrigin) String() string {
	switch o {
	case OriginHSMGenerated:
		return "hsm_generated"
	case OriginImported:
		return "imported"
	case OriginUnknown:
		return "unknown"
	default:
		return "unattested"
	}
}

// KeyOriginProvider is an OPTIONAL extension a TokenIssuer MAY implement
// to report the cryptographic origin of each signing key by key ID (kid).
// This is a PER-KEY method so rotation events (two keys, same issuer,
// different origins) produce correct per-kid attestation.
//
// Callers type-assert the TokenIssuer to KeyOriginProvider; a non-nil
// result indicates the issuer can attest origins. Implementations MUST be
// concurrency-safe and SHOULD cache the result (origin never changes for
// a key's lifetime).
type KeyOriginProvider interface {
	// KeyOrigin returns the origin of the key identified by kid. An
	// unknown kid returns OriginUnknown, nil.
	KeyOrigin(ctx context.Context, kid string) (KeyOrigin, error)
}

// PageQuery is the pushdown query carried by every optional pagination SPI
// (see the Paginated* interfaces below). It mirrors the grpcadmin List RPC
// wire contract minus the opaque page_token: the handler validates the
// filter/order_by spec first, canonicalizes the sort field, and passes the
// RAW filter expression down so stores and the fallback path share one
// mini-grammar (ParseFilterExpr).
//
// The SPI is the store-side keyset authority: After is an opaque cursor the
// store itself minted (its own encoding of the last row's sort key +
// tiebreaker), and the handler only wraps those bytes in a MAC'd token. The
// store MUST NOT rely on the handler understanding its cursor format.
type PageQuery struct {
	Limit   int    // rows to fetch, already clamped to [1, maxAdminPageSize]
	OrderBy string // canonical field, "" = default (id asc)
	Desc    bool   // true = descending
	Filter  string // mini-grammar expr ("field:value" | "field eq value"), "" = match all
	After   []byte // opaque keyset cursor from the previous response; nil = first page
}

// PaginatedClientStore is an OPTIONAL extension a core.ClientStore MAY
// implement to push List's filter/sort/pagination down into the backend
// instead of the grpcadmin fallback's full List() -> filter -> sort ->
// offset slice. The pattern mirrors TenantScopedClientStore: callers
// type-assert before using, so adding this interface never breaks an
// existing ClientStore implementation.
//
// ListPage returns the page's rows, an opaque next-cursor (nil when the
// page ended at the tail), and a totalHint: the approximate number of rows
// matching Filter (ignoring OrderBy/After/Limit) for UI display, or -1
// when the backend has no cheap count. Backends MUST NOT full-scan to
// compute totalHint; memory backends return the exact filtered count.
type PaginatedClientStore interface {
	ListPage(ctx context.Context, q PageQuery) ([]*Client, []byte, int, error)
}

// ClientExpiryLister is the windowed counterpart of PaginatedClientStore for
// ListExpiring, mirroring the clientrotation.ClientRotationLister precedent
// (durable backends already implement time-window index queries). cutoff is
// the exclusive window horizon (now + requested look-ahead); rows with a
// zero SecretExpiresAt (legacy/public clients) never match.
type ClientExpiryLister interface {
	ListExpiringPage(ctx context.Context, cutoff time.Time, q PageQuery) ([]*Client, []byte, int, error)
}

// PaginatedUserProvider is the OPTIONAL user counterpart of
// PaginatedClientStore for a core.UserProvider. Same contract: keyset
// pushdown with a List() fallback for backends without the extension.
type PaginatedUserProvider interface {
	ListPage(ctx context.Context, q PageQuery) ([]*User, []byte, int, error)
}

// PaginatedSessionLister is the OPTIONAL session counterpart for a
// core.SessionManager. userID "" = every session (the ListAll fallback);
// non-empty = that user's active sessions (the ListByUser fallback).
type PaginatedSessionLister interface {
	ListPage(ctx context.Context, userID string, q PageQuery) ([]*Session, []byte, int, error)
}

// ParseFilterExpr splits the proto's tiny 'field:value' | 'field eq value'
// filter mini-grammar. An empty expr means "match all" (ok=false signals the
// caller to skip filtering, not an error). A non-empty expr that matches
// neither form yields field="" with ok=true — every entity matcher's field
// switch treats an unrecognized field as an error, so a malformed filter is
// rejected rather than silently ignored (STRICT: "bad filter value" must
// error, only a genuinely absent filter matches all).
//
// Shared by grpcadmin AND every store implementation so the two paths cannot
// drift apart. Deliberately NOT the SCIM RFC 7644 filter grammar
// (protocols/scim/filter.go) — that parser is unexported, HTTP-request-shaped,
// and far heavier than this proto's mini-grammar warrants.
func ParseFilterExpr(expr string) (field, value string, ok bool) {
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

// --- Client filter/sort semantics (fallback + memory-store reference) ---
//
// Every function here is row-independent validation + pure matching/
// comparison, extracted from grpcadmin's per-RPC matchers so the fallback
// path and the memory-store ListPage implementations share one semantics and
// one error text ("unsupported filter field %q", "invalid filter value for
// active: %q", "unsupported order_by field %q"). grpcadmin wraps the plain
// errors into InvalidArgument status errors with byte-identical messages.

// ValidateClientFilter checks one filter field/value pair without touching
// any row. id/name accept any value; active requires a ParseBool value.
func ValidateClientFilter(field, value string) error {
	switch strings.ToLower(field) {
	case "id", "name":
		return nil
	case "active":
		if _, err := strconv.ParseBool(value); err != nil {
			return fmt.Errorf("invalid filter value for active: %q", value)
		}
		return nil
	default:
		return fmt.Errorf("unsupported filter field %q", field)
	}
}

// ClientMatches evaluates one filter field against a client. Users field set
// is documented separately (UserMatches) — the two entities intentionally
// support different filter fields (Client has no email/created_at).
func ClientMatches(c *Client, field, value string) (bool, error) {
	switch strings.ToLower(field) {
	case "id":
		return c.ID == value, nil
	case "name":
		return strings.Contains(strings.ToLower(c.Name), strings.ToLower(value)), nil
	case "active":
		want, err := strconv.ParseBool(value)
		if err != nil {
			return false, fmt.Errorf("invalid filter value for active: %q", value)
		}
		return c.Active == want, nil
	default:
		return false, fmt.Errorf("unsupported filter field %q", field)
	}
}

// ValidateClientOrderBy checks one order_by field without touching any row.
// 'created_at' aliases to the id default because core.Client has no
// CreatedAt field (unlike core.User) — the documented order_by asymmetry
// between the two List RPCs.
func ValidateClientOrderBy(field string) error {
	switch strings.ToLower(field) {
	case "", "id", "created_at", "name":
		return nil
	default:
		return fmt.Errorf("unsupported order_by field %q", field)
	}
}

// ClientSortKey returns the canonical string form of a client's sort key for
// the given canonical order field ("" = id). Used by memory stores so their
// sort, their keyset search, and their cursor bytes all share one encoding.
func ClientSortKey(c *Client, field string) string {
	switch strings.ToLower(field) {
	case "name":
		return c.Name
	case "", "id", "created_at":
		return c.ID
	}
	return c.ID
}

// CompareClients orders two clients by the canonical sort field, breaking
// ties by ID — the strict total order keyset paging relies on. Mirrors the
// fallback path's comparators exactly (the tiebreaker only pins the order of
// rows whose sort keys are equal, which the old stable sort left to map
// iteration).
func CompareClients(a, b *Client, field string) int {
	switch strings.ToLower(field) {
	case "name":
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
	case "", "id", "created_at":
	}
	return strings.Compare(a.ID, b.ID)
}

// --- User filter/sort semantics ---

// ValidateUserFilter checks one filter field/value pair. Field set is the
// STABLE proto-package contract: id/provider/external_id (exact) + name/email
// (substring).
func ValidateUserFilter(field, value string) error {
	switch strings.ToLower(field) {
	case "id", "provider", "external_id", "name", "email":
		return nil
	default:
		return fmt.Errorf("unsupported filter field %q", field)
	}
}

// UserMatches evaluates one filter field against a user.
func UserMatches(u *User, field, value string) (bool, error) {
	switch strings.ToLower(field) {
	case "id":
		return u.ID == value, nil
	case "provider":
		return u.Provider == value, nil
	case "external_id":
		return u.ExternalID == value, nil
	case "name":
		return strings.Contains(strings.ToLower(u.Name), strings.ToLower(value)), nil
	case "email":
		return strings.Contains(strings.ToLower(u.Email), strings.ToLower(value)), nil
	default:
		return false, fmt.Errorf("unsupported filter field %q", field)
	}
}

// ValidateUserOrderBy checks one order_by field. Unlike ClientSortKey's
// created_at alias, 'created_at' maps to the real core.User.CreatedAt field
// here (core.User has one; core.Client does not).
func ValidateUserOrderBy(field string) error {
	switch strings.ToLower(field) {
	case "", "id", "created_at", "provider":
		return nil
	default:
		return fmt.Errorf("unsupported order_by field %q", field)
	}
}

// UserSortKey returns the canonical string form of a user's sort key. The
// created_at form is UTC RFC3339Nano, whose lexicographic order equals
// instant order — so memory stores can sort, search, and encode cursors with
// one string encoding while the fallback path keeps time.Before semantics.
func UserSortKey(u *User, field string) string {
	switch strings.ToLower(field) {
	case "created_at":
		return u.CreatedAt.UTC().Format(time.RFC3339Nano)
	case "provider":
		return u.Provider
	case "", "id":
		return u.ID
	}
	return u.ID
}

// CompareUsers orders two users by the canonical sort field, breaking ties
// by ID.
func CompareUsers(a, b *User, field string) int {
	switch strings.ToLower(field) {
	case "created_at":
		if a.CreatedAt.Before(b.CreatedAt) {
			return -1
		}
		if a.CreatedAt.After(b.CreatedAt) {
			return 1
		}
	case "provider":
		if c := strings.Compare(a.Provider, b.Provider); c != 0 {
			return c
		}
	case "", "id":
	}
	return strings.Compare(a.ID, b.ID)
}

// CompareSessions orders two sessions by ID (the only sort key the session
// List RPC exposes).
func CompareSessions(a, b *Session) int {
	return strings.Compare(a.ID, b.ID)
}

// --- Memory-store keyset machinery ---
//
// The cursor bytes exchanged with the handler are STORE-OPAQUE: the handler
// MACs them without interpreting them. Memory backends share one compact
// encoding here — base64url(sortKey) + "." + base64url(tiebreaker) — which is
// 0x00-free so the v1 page-token payload's 0x00-partitioning stays
// unambiguous, and dot-free per part so the two halves always split cleanly.
// A durable backend may choose its own encoding (e.g. raw column values).

// EncodeKeysetCursor packs (sortKey, tiebreaker) into the opaque cursor
// bytes memory backends mint for their ListPage.
func EncodeKeysetCursor(sortKey, tiebreaker string) []byte {
	return []byte(base64.RawURLEncoding.EncodeToString([]byte(sortKey)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(tiebreaker)))
}

// DecodeKeysetCursor reverses EncodeKeysetCursor. ok=false signals a cursor
// this store never minted (a direct-store caller passing foreign bytes; the
// handler's MAC check already rules that out on the RPC path).
func DecodeKeysetCursor(after []byte) (sortKey, tiebreaker string, ok bool) {
	parts := strings.SplitN(string(after), ".", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	k, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", "", false
	}
	id, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", false
	}
	return string(k), string(id), true
}

// CompareKeyID compares two (sortKey, tiebreaker) pairs lexicographically —
// the tuple order every keyset predicate is built on.
func CompareKeyID(k1, id1, k2, id2 string) int {
	if c := strings.Compare(k1, k2); c != 0 {
		return c
	}
	return strings.Compare(id1, id2)
}

// SortKeyset stably sorts rows by their (sortKey, tiebreaker) tuple in the
// requested direction. Stores pass ONE keyID function to both SortKeyset and
// KeysetSlice so the sort, the cursor search, and the minted cursor bytes can
// never disagree.
func SortKeyset[T any](rows []T, desc bool, keyID func(T) (string, string)) {
	sort.SliceStable(rows, func(i, j int) bool {
		ki, idi := keyID(rows[i])
		kj, idj := keyID(rows[j])
		c := CompareKeyID(ki, idi, kj, idj)
		if desc {
			return c > 0
		}
		return c < 0
	})
}

// KeysetSlice applies keyset pagination to rows already sorted by the
// (sortKey, tiebreaker) tuple in the requested direction: binary-searches
// q.After (first row strictly after the cursor under the current direction),
// slices q.Limit rows, and mints the next cursor from the last row when more
// rows remain (nil when the page ended at the tail). total is the number of
// rows before slicing — the exact totalHint memory backends report.
func KeysetSlice[T any](rows []T, q PageQuery, keyID func(T) (string, string)) (items []T, next []byte, total int, err error) {
	total = len(rows)
	limit := q.Limit
	if limit < 1 {
		limit = 1
	}
	start := 0
	if len(q.After) > 0 {
		k, id, ok := DecodeKeysetCursor(q.After)
		if !ok {
			return nil, nil, 0, fmt.Errorf("invalid keyset cursor")
		}
		start = sort.Search(len(rows), func(i int) bool {
			ki, idi := keyID(rows[i])
			c := CompareKeyID(ki, idi, k, id)
			if q.Desc {
				return c < 0
			}
			return c > 0
		})
	}
	end := start + limit
	if end > len(rows) {
		end = len(rows)
	}
	items = rows[start:end]
	if end < len(rows) {
		k, id := keyID(rows[end-1])
		next = EncodeKeysetCursor(k, id)
	}
	return items, next, total, nil
}

// --- Client redirect-URI policy (exact allowlist + opt-in patterns) ---
// The redirect gates (login/PAR/finish-login/end_session) sit beside the
// client row-helper semantics: types.go is at its 500-line hard ceiling.
// Grammar: docs/design/redirect-uri-patterns.md + redirect_patterns.go.

// IsRedirectURIValid checks if the given redirect URI is registered: an
// exact-match hit on RedirectURIs, or a hit against any RedirectURIPatterns
// entry. Zero patterns = exact-match only (pre-feature behavior); an invalid
// pattern never widens the gate (MatchRedirectURIPattern degrades to
// no-match, so a stale store row cannot loosen the allowlist).
func (c *Client) IsRedirectURIValid(uri string) bool {
	if slices.Contains(c.RedirectURIs, uri) {
		return true
	}
	for _, pattern := range c.RedirectURIPatterns {
		if MatchRedirectURIPattern(pattern, uri) {
			return true
		}
	}
	return false
}

// IsPostLogoutRedirectURIValid checks the post-logout redirect allowlist.
func (c *Client) IsPostLogoutRedirectURIValid(uri string) bool {
	return slices.Contains(c.PostLogoutRedirectURIs, uri)
}
