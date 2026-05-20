package sso

import "context"

// SubjectClientIndex tracks the set of clients a subject has had
// active tokens issued for. Optional SPI: when wired, OIDC Back-
// Channel Logout 1.0 fans out logout_token POSTs to every client
// in the subject's active set (true single sign-out) — without it
// the AS only notifies the client present in the bearer / id_token_hint
// at logout time.
//
// The index is intentionally "best-effort active set" rather than a
// strict source of truth: stale entries simply produce one extra
// logout_token POST per stale client, which a well-behaved RP
// silently ignores (the RP has no matching session to invalidate).
// Implementations SHOULD garbage-collect old entries on a TTL the
// operator picks, but the SDK doesn't mandate a specific lifetime.
//
// Multi-replica deployments need a shared backend (Redis, SQL, etc.).
// The default in-memory implementation
// (defaultimpl.NewMemorySubjectClientIndex) is single-replica only —
// notifications minted on replica A won't fan out to a client whose
// last issuance happened on replica B until that replica also sees
// a logout.
type SubjectClientIndex interface {
	// RecordAccess marks (subject, clientID) as live. Idempotent —
	// repeated calls for the same pair are fine. Implementations
	// MAY refresh a "last-seen" timestamp on each call.
	RecordAccess(ctx context.Context, subject, clientID string) error

	// ListClients returns every client id the subject has been
	// seen with that is still considered active. Order is
	// implementation-defined; callers MUST treat the result as a
	// set (dedupe on their end is not required — the store
	// already enforces uniqueness).
	ListClients(ctx context.Context, subject string) ([]string, error)

	// Forget removes the (subject, clientID) pair. Called by the
	// AS after a successful back-channel logout fan-out so the
	// next logout for the same subject doesn't re-notify a
	// client that already tore down its session. nil-safe on
	// unknown pairs.
	Forget(ctx context.Context, subject, clientID string) error
}
