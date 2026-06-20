package scim

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"

	"github.com/snaplink/sso/interfaces/admin"
)

// Default pagination bounds (RFC 7644 §3.4.2.4). A request that omits
// count gets defaultPageSize; count is clamped to maxPageSize so a client
// can't ask the server to materialize an unbounded page.
const (
	defaultPageSize = 100
	maxPageSize     = 200
)

// paginationParams parses startIndex + count (RFC 7644 §3.4.2.4), both
// 1-based. startIndex < 1 is clamped to 1 per the spec; count < 0 is an
// error (negative pages are nonsensical); count == 0 means "return no
// resources, just the count" and is honored; an omitted count defaults to
// defaultPageSize; count above maxPageSize is clamped down.
func paginationParams(r *http.Request) (startIndex, count int, err error) {
	startIndex = 1
	if v := r.URL.Query().Get("startIndex"); v != "" {
		n, perr := strconv.Atoi(v)
		if perr != nil {
			return 0, 0, errors.New("startIndex must be an integer")
		}
		if n < 1 {
			n = 1 // RFC 7644: values < 1 are interpreted as 1.
		}
		startIndex = n
	}

	count = defaultPageSize
	if v := r.URL.Query().Get("count"); v != "" {
		n, perr := strconv.Atoi(v)
		if perr != nil {
			return 0, 0, errors.New("count must be an integer")
		}
		if n < 0 {
			return 0, 0, errors.New("count must not be negative")
		}
		count = n
	}
	if count > maxPageSize {
		count = maxPageSize
	}
	return startIndex, count, nil
}

// pageBounds translates a 1-based startIndex + count into a [lo,hi) slice
// window over a result set of size total, clamped to the bounds (RFC 7644
// §3.4.2.4). Shared by the User and Group list handlers so the clamping is
// identical across resource types.
func pageBounds(startIndex, count, total int) (lo, hi int) {
	lo = startIndex - 1
	if lo > total {
		lo = total
	}
	hi = lo + count
	if hi > total {
		hi = total
	}
	return lo, hi
}

// randomID mints a 128-bit hex resource id. SCIM clients don't supply an
// id on create (RFC 7643 §3.1 — id is server-assigned, read-only), so the
// server owns the scheme; callers treat it as opaque.
func randomID() string {
	var b [16]byte
	// crypto/rand.Read never returns a short read; the error is only for
	// catastrophic entropy-source failure, which we can't recover from.
	if _, err := rand.Read(b[:]); err != nil {
		panic("scim: entropy source failure: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// actorFromContext bridges to the admin middleware's stamped actor so
// SCIM audit events attribute the provisioning call to the admin
// principal. Returns ok=false when the request didn't pass through the
// admin middleware (e.g. a direct in-process call or a test).
func actorFromContext(ctx context.Context) (userID, clientID string, ok bool) {
	return admin.ActorFromContext(ctx)
}
