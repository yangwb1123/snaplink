package scim

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/shared/core"
)

// SCIM resource versioning + conditional requests (RFC 7644 §3.14). Every
// returned resource carries a meta.version ETag derived deterministically
// from its content, and the same value is echoed in the HTTP ETag header.
// Clients use it for optimistic concurrency: If-Match on a write rejects a
// stale update (412), and If-None-Match on a read short-circuits an
// unchanged resource (304). WHY content-derived rather than a stored
// monotonic counter: core.User / permissions.Role carry no version column,
// and a content hash needs no new SPI — two resources with identical
// attributes hash identically, which is exactly the ETag contract.

// headerETag / headerIfMatch / headerIfNoneMatch are the HTTP conditional
// headers (RFC 7232 §2.3 / §3). Centralized so no literal header name leaks.
const (
	headerETag        = "ETag"
	headerIfMatch     = "If-Match"
	headerIfNoneMatch = "If-None-Match"
)

// etagWildcard is the "*" entity-tag that matches any existing resource
// (RFC 7232 §3.1/§3.2): If-Match:* proceeds iff the resource exists (it
// always does at the point we check), If-None-Match:* on a GET means "304
// iff it exists" which for an existing resource is always a match.
const etagWildcard = "*"

// versionTagLen is the number of hex chars of the SHA-256 digest kept in
// the weak ETag. 32 hex chars (128 bits) is collision-resistant for a
// directory's resource population while keeping the header compact.
const versionTagLen = 32

// computeVersion returns the weak ETag for a resource's content as
// W/"<sha256-prefix>". The resource is marshaled with its existing
// meta.version cleared so the hash is over the content only (a version that
// folded itself in would never be reproducible). Marshal failure is
// impossible for these plain structs, but on the off chance it errors the
// version is empty (the conditional helpers then degrade to unconditional,
// never to a wrong match).
func computeVersion(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return `W/"` + hex.EncodeToString(sum[:])[:versionTagLen] + `"`
}

// userVersion computes the ETag for a User resource with meta.version
// excluded from the hashed content (so the version is reproducible).
func userVersion(res Resource) string {
	res.Meta = metaForHash(res.Meta)
	return computeVersion(res)
}

// groupVersion computes the ETag for a Group resource, mirroring
// userVersion.
func groupVersion(g GroupResource) string {
	g.Meta = metaForHash(g.Meta)
	return computeVersion(g)
}

// metaForHash returns a copy of meta with the Version field cleared, so the
// computed version never depends on a previously stamped version. A nil
// meta passes through unchanged.
func metaForHash(m *Meta) *Meta {
	if m == nil {
		return nil
	}
	cp := *m
	cp.Version = ""
	return &cp
}

// versionMatches reports whether a client-supplied entity-tag (one element
// of an If-Match / If-None-Match list, or "*") matches the resource's
// current version. The comparison is the SCIM/HTTP weak-comparison: the
// optional weak prefix (W/) and surrounding quotes are normalized away so
// W/"abc", "abc", and abc all match version W/"abc". "*" matches any
// existing resource.
func versionMatches(clientTag, current string) bool {
	clientTag = strings.TrimSpace(clientTag)
	if clientTag == etagWildcard {
		return true
	}
	return normalizeTag(clientTag) == normalizeTag(current)
}

// normalizeTag strips the weak indicator and surrounding double-quotes from
// an entity-tag for comparison (RFC 7232 weak comparison). It is
// intentionally lenient so a client that omits the W/ prefix or the quotes
// still interoperates.
func normalizeTag(tag string) string {
	tag = strings.TrimSpace(tag)
	tag = strings.TrimPrefix(tag, "W/")
	tag = strings.TrimPrefix(tag, "w/")
	tag = strings.Trim(tag, `"`)
	return tag
}

// ifMatchSatisfied evaluates an If-Match precondition (RFC 7232 §3.1) on a
// write (PUT/PATCH/DELETE). It returns proceed=false when the header is
// present and NO listed tag matches the resource's current version — the
// caller then responds 412. An absent header proceeds unconditionally
// (preconditions are opt-in per the spec).
func ifMatchSatisfied(r *http.Request, current string) bool {
	raw := r.Header.Get(headerIfMatch)
	if strings.TrimSpace(raw) == "" {
		return true
	}
	for _, tag := range splitTags(raw) {
		if versionMatches(tag, current) {
			return true
		}
	}
	return false
}

// ifNoneMatchMatches evaluates an If-None-Match precondition (RFC 7232
// §3.2) on a read (GET). It returns true when the header is present and
// SOME listed tag matches the current version — the caller then responds
// 304 Not Modified. An absent header returns false (serve the body).
func ifNoneMatchMatches(r *http.Request, current string) bool {
	raw := r.Header.Get(headerIfNoneMatch)
	if strings.TrimSpace(raw) == "" {
		return false
	}
	for _, tag := range splitTags(raw) {
		if versionMatches(tag, current) {
			return true
		}
	}
	return false
}

// splitTags splits a comma-separated entity-tag list (RFC 7232 allows e.g.
// `If-Match: "a", "b"`). A bare "*" is returned as a single element.
func splitTags(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// stampUserVersion sets res.Meta.Version to the resource's computed ETag,
// allocating Meta if absent, and returns the version so the caller can also
// set the HTTP ETag header. Keeping the version on meta AND in the header
// matches RFC 7644 §3.14 (both carry the same value).
func stampUserVersion(res *Resource) string {
	v := userVersion(*res)
	if res.Meta == nil {
		res.Meta = &Meta{ResourceType: resourceTypeUser}
	}
	res.Meta.Version = v
	return v
}

// stampGroupVersion mirrors stampUserVersion for a Group resource.
func stampGroupVersion(g *GroupResource) string {
	v := groupVersion(*g)
	if g.Meta == nil {
		g.Meta = &Meta{ResourceType: resourceTypeGroup}
	}
	g.Meta.Version = v
	return v
}

// writeUserResource stamps meta.version, sets the ETag response header, and
// writes the User resource as the SCIM JSON body. Single seam so every User
// response (create/get/replace/patch) advertises a consistent ETag.
func (h *Handler) writeUserResource(w http.ResponseWriter, code int, res Resource) {
	v := stampUserVersion(&res)
	if v != "" {
		w.Header().Set(headerETag, v)
	}
	h.writeJSON(w, code, res)
}

// writeGroupResource mirrors writeUserResource for a Group resource.
func (h *Handler) writeGroupResource(w http.ResponseWriter, code int, g GroupResource) {
	v := stampGroupVersion(&g)
	if v != "" {
		w.Header().Set(headerETag, v)
	}
	h.writeJSON(w, code, g)
}

// currentUserVersion computes the ETag of the stored user as it is NOW,
// for an If-Match precondition check on a write. It mirrors what a GET would
// return (same projection + version) so a client's cached ETag compares
// against the same value the read handed it.
func currentUserVersion(u *core.User, location string) string {
	return userVersion(UserToResource(u, location))
}

// currentGroupVersion computes the ETag of the stored group as it is NOW,
// for an If-Match precondition check, mirroring currentUserVersion.
func currentGroupVersion(role permissions.Role, memberIDs []string, location string) string {
	return groupVersion(RoleToGroup(role, memberIDs, location))
}

// preconditionFailed is the SCIM error for an If-Match mismatch on a write
// (RFC 7644 §3.14 / RFC 7232 §4.2): the client's expected version is stale,
// so the write is refused with 412 rather than silently overwriting a
// concurrent change.
func preconditionFailed() ErrorResponse {
	return newError(http.StatusPreconditionFailed, "", "resource version does not match If-Match precondition")
}
