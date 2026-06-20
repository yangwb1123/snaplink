package middleware

import (
	"context"
	"net/http"
)

// subjectKey is the unexported context key for the authenticated
// subject string. An unexported struct type prevents collisions with
// keys from other packages.
type subjectKey struct{}

// WithSubject returns a context carrying sub as the authenticated
// subject. Callers (e.g. a bearer-validation middleware that runs
// before the rate limiter) store the validated sub claim here so
// downstream components — including [KeyBySubject] — can read it
// without re-parsing the token.
func WithSubject(ctx context.Context, sub string) context.Context {
	return context.WithValue(ctx, subjectKey{}, sub)
}

// SubjectFromContext returns the authenticated subject previously
// stored by [WithSubject]. Returns an empty string when no subject
// has been stored (unauthenticated request, or middleware ran in the
// wrong order).
func SubjectFromContext(r *http.Request) string {
	sub, _ := r.Context().Value(subjectKey{}).(string)
	return sub
}
