package oauthwire

import (
	"errors"

	"github.com/yangwb1123/snaplink/shared/core"
)

// ErrFormOnly is the internal dispatch signal returned by
// BindParamsFormOnly when the request's Content-Type is not
// application/x-www-form-urlencoded (JSON, missing, or any other
// media type). It is an internal sentinel only — it is NEVER written
// to the wire; the four credential handlers map it to the documented
// 415 {"error":"invalid_request"} envelope. Exported because the
// mapping sites span two packages (interfaces/sso + protocols/oauth).
var ErrFormOnly = errors.New("oauth: form-urlencoded content type required")

// BindParamsFormOnly is the strict-wire sibling of BindParams: it
// accepts ONLY application/x-www-form-urlencoded bodies and returns
// ErrFormOnly for any other Content-Type BEFORE the body is read. The
// dispatch contract (B4-4 D5):
//
//  1. Dispatch is a pure function of the normalized Content-Type
//     (normalizedMediaType — same parameter stripping + lowercase
//     tolerance as BindParams, so "application/x-www-form-urlencoded;
//     charset=UTF-8" binds).
//  2. decodeSingleJSON is unreachable here — the strict binder is a
//     separate function, never a flag inside BindParams.
//  3. r.ParseForm runs BEFORE formIntoStruct — a parse error returns
//     before any partial bind.
//  4. ErrFormOnly is returned only from the media-type branch, never
//     wrapped, never produced by the form path. Malformed
//     percent-encoding under a form Content-Type is a ParseForm error,
//     NOT ErrFormOnly.
//  5. A zero-struct form body (empty body WITH the form Content-Type)
//     binds successfully and hits the unchanged per-endpoint 400
//     validation — media-type enforcement never becomes a body
//     validation oracle.
func BindParamsFormOnly(ctx core.HandlerContext, v any) error {
	r := ctx.Request()
	if normalizedMediaType(r) != "application/x-www-form-urlencoded" {
		return ErrFormOnly
	}
	return bindForm(r, v)
}
