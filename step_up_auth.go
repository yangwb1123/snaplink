package sso

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// RFC 9470 — OAuth 2.0 Step Up Authentication Challenge Protocol
// for OAuth 2.0.
//
// Resource servers use this to signal "the bearer token's
// authentication is too weak for the operation requested — re-
// authenticate with a stronger ACR or fresher auth_time". The
// challenge ships on a 401 `WWW-Authenticate: Bearer ...` header;
// the RP catches it, re-initiates /auth/login with `acr_values=`
// (already wired) and/or `max_age=` (already wired), and the AS
// mints a stronger token.
//
// This file provides the AS-side helper resource servers use to
// BUILD the challenge header; the actual UI flow lives in the
// RP. Exposed because:
//
//   - Resource servers in the same monorepo often share this SDK
//     and want a canonical builder rather than reinventing the
//     header.
//   - The error code spelling + field ordering is finicky enough
//     to deserve one tested place.

// ErrInsufficientUserAuthentication is the RFC 9470 §3 wire error
// code resource servers stamp on the challenge. SPAs branch on
// this to know "re-initiate auth with stronger params" vs
// "re-authenticate normally" (invalid_token).
const ErrInsufficientUserAuthentication = "insufficient_user_authentication"

// StepUpChallenge describes a resource-server demand for stronger
// authentication. All fields are optional individually but at
// least one MUST be set — an empty challenge is a misconfigured
// resource server and the builder returns an error.
type StepUpChallenge struct {
	// ACRValues lists the ACR values the resource server demands,
	// in preference order. Stamped as `acr_values="<space-sep>"`
	// on the challenge header. RP echoes the chosen value as the
	// `acr_values` request param on /auth/login.
	ACRValues []string

	// MaxAge requests a fresh authentication within MaxAge
	// seconds — the resource sees the access token's auth_time
	// outside that window and challenges. RP echoes it as
	// `max_age=` on /auth/login.
	MaxAge int

	// Realm is the optional RFC 7235 `realm="..."` parameter
	// resource servers use to scope the challenge to a specific
	// protected resource set. Empty omits the parameter.
	Realm string

	// Description is a human-readable RFC 6750 `error_description`
	// surfaced in logs and developer tooling. Stays out of the
	// authentication decision — SPAs MUST branch on the error
	// code, not the description.
	Description string
}

// BuildStepUpChallenge composes the WWW-Authenticate header value
// per RFC 9470 §3. Returns an error when the challenge would be
// degenerate (no demand fields set) — RFC 9470 has no semantics for
// a step-up that demands nothing.
//
// Wire shape:
//
//	Bearer error="insufficient_user_authentication",
//	  error_description="...", realm="...",
//	  acr_values="urn:high urn:medium", max_age="60"
//
// All values are quoted per RFC 7235 §2.1 quoted-string syntax.
// Embedded quotes / backslashes are backslash-escaped so an
// attacker-controlled description can't break out of the
// quoted-string context.
func BuildStepUpChallenge(c StepUpChallenge) (string, error) {
	if len(c.ACRValues) == 0 && c.MaxAge == 0 {
		return "", errors.New("step_up: challenge MUST demand acr_values or max_age")
	}
	parts := []string{"error=" + quoteAuthParam(ErrInsufficientUserAuthentication)}
	if c.Description != "" {
		parts = append(parts, "error_description="+quoteAuthParam(c.Description))
	}
	if c.Realm != "" {
		parts = append(parts, "realm="+quoteAuthParam(c.Realm))
	}
	if len(c.ACRValues) > 0 {
		parts = append(parts, "acr_values="+quoteAuthParam(strings.Join(c.ACRValues, " ")))
	}
	if c.MaxAge > 0 {
		parts = append(parts, "max_age="+quoteAuthParam(strconv.Itoa(c.MaxAge)))
	}
	return "Bearer " + strings.Join(parts, ", "), nil
}

// quoteAuthParam wraps a value in RFC 7235 quoted-string form,
// escaping internal quote + backslash. Empty inputs become `""`.
func quoteAuthParam(v string) string {
	if v == "" {
		return `""`
	}
	var b strings.Builder
	b.Grow(len(v) + 2)
	b.WriteByte('"')
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '"' || c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	b.WriteByte('"')
	return b.String()
}

// MustBuildStepUpChallenge is BuildStepUpChallenge that panics on
// error — convenience for callers with statically-known challenge
// shapes (e.g. a single global "high-assurance" challenge built
// at server startup, not per-request).
func MustBuildStepUpChallenge(c StepUpChallenge) string {
	header, err := BuildStepUpChallenge(c)
	if err != nil {
		panic(fmt.Sprintf("step_up: build: %v", err))
	}
	return header
}
