package caep

import (
	"context"
	"errors"

	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
)

// StoreRevoker is the default SubjectRevoker: it revokes ALL of a local
// subject's access by composing the EXACT same revocation seams the
// /token/revoke-all endpoint and the compliance Eraser drive — refresh
// tokens via oauth.RefreshTokenSubjectIndex.DeleteAllForSubject (per
// client, enumerated from the ClientStore) and sessions via
// SessionManager.ListByUser + Destroy. It deliberately does NOT delete the
// user account (unlike the Eraser): the receiver's job is to KILL ACCESS,
// not erase the subject — an upstream session-revoked event should log the
// user out, not delete them.
//
// Reusing these seams (rather than inventing a new revocation path) means
// the receiver's action is identical to a locally-initiated "logout
// everywhere": same single-use semantics, same store behavior, same
// idempotence.
type StoreRevoker struct {
	// Sessions destroys the subject's active server-side sessions. nil ⇒
	// the session leg is skipped (refresh-token-only revocation).
	Sessions core.SessionManager

	// Refresh revokes refresh tokens per (subject, client). Requires
	// Clients to enumerate the clients (the SPI is per-client). nil ⇒ the
	// refresh leg is skipped.
	Refresh oauth.RefreshTokenSubjectIndex

	// Clients enumerates registered clients for the per-client refresh
	// revocation. nil ⇒ the refresh leg is skipped.
	Clients core.ClientStore

	// TrustedDevices revokes every "remember this device" MFA-skip grant
	// for the subject (WithTrustedDeviceRevocation). nil ⇒ the leg is
	// skipped — byte-identical to a StoreRevoker built before this field
	// existed. Wired so an upstream session-revoked/account-disabled SET
	// can't leave a standing local MFA-skip grant that outlives the
	// compromise signal it was supposed to answer.
	TrustedDevices core.TrustedDeviceStore
}

// StoreRevokerOption configures an optional StoreRevoker leg beyond the
// three NewStoreRevoker requires directly. Additive: existing 3-arg call
// sites are unaffected.
type StoreRevokerOption func(*StoreRevoker)

// WithTrustedDeviceRevocation adds the trusted-device leg to a StoreRevoker
// — see StoreRevoker.TrustedDevices.
func WithTrustedDeviceRevocation(store core.TrustedDeviceStore) StoreRevokerOption {
	return func(r *StoreRevoker) { r.TrustedDevices = store }
}

// NewStoreRevoker builds a StoreRevoker. At least one revocation leg must
// be wireable: either a SessionManager, or BOTH a RefreshTokenSubjectIndex
// and a ClientStore, or (via opts) a TrustedDeviceStore. A revoker that can
// do NOTHING is a misconfiguration (it would silently no-op every
// validated SET), so it errors.
func NewStoreRevoker(sessions core.SessionManager, refresh oauth.RefreshTokenSubjectIndex, clients core.ClientStore, opts ...StoreRevokerOption) (*StoreRevoker, error) {
	r := &StoreRevoker{Sessions: sessions, Refresh: refresh, Clients: clients}
	for _, opt := range opts {
		opt(r)
	}
	canSession := r.Sessions != nil
	canRefresh := r.Refresh != nil && r.Clients != nil
	canTrustedDevices := r.TrustedDevices != nil
	if !canSession && !canRefresh && !canTrustedDevices {
		return nil, errors.New("caep: StoreRevoker needs a SessionManager and/or (RefreshTokenSubjectIndex + ClientStore) and/or (via WithTrustedDeviceRevocation) a TrustedDeviceStore")
	}
	return r, nil
}

// RevokeAllForSubject revokes the subject's refresh tokens (across every
// client) and destroys their sessions. Credentials-first ordering mirrors
// the Eraser: kill the long-lived refresh tokens before the sessions, so a
// failure midway still leaves the subject MORE locked out, never less.
// Best-effort across both legs and across clients (a single store/client
// failure is collected, not a reason to abandon the rest) — revoking is the
// safe direction. Idempotent: a second call finds nothing.
func (r *StoreRevoker) RevokeAllForSubject(ctx context.Context, localUserID string) (RevocationResult, error) {
	if localUserID == "" {
		return RevocationResult{}, errors.New("caep: empty subject")
	}
	var res RevocationResult
	var errs []error

	r.revokeRefreshLeg(ctx, localUserID, &res, &errs)
	r.revokeSessionLeg(ctx, localUserID, &res, &errs)
	// Trusted-device MFA-skip grants — last, since it's the least impactful
	// leg (it only affects a FUTURE login's step-up decision, not any
	// currently-live credential) but still required: a compromise signal
	// that revoked every session and refresh token yet left a
	// trusted-device grant standing would let the attacker back in via a
	// plain password plus that old grant, skipping MFA entirely.
	r.revokeTrustedDeviceLeg(ctx, localUserID, &res, &errs)

	return res, errors.Join(errs...)
}

// revokeRefreshLeg deletes localUserID's refresh tokens per client (the
// same per-client loop the Eraser uses; the SPI is per-client by design).
// No-op when the leg isn't wired.
func (r *StoreRevoker) revokeRefreshLeg(ctx context.Context, localUserID string, res *RevocationResult, errs *[]error) {
	if r.Refresh == nil || r.Clients == nil {
		return
	}
	clients, err := r.Clients.List(ctx)
	if err != nil {
		*errs = append(*errs, err)
		return
	}
	for _, c := range clients {
		n, derr := r.Refresh.DeleteAllForSubject(ctx, localUserID, c.ID)
		if derr != nil {
			*errs = append(*errs, derr)
			continue
		}
		res.RefreshTokensRevoked += n
	}
}

// revokeSessionLeg destroys every active server-side session for
// localUserID. No-op when the leg isn't wired.
func (r *StoreRevoker) revokeSessionLeg(ctx context.Context, localUserID string, res *RevocationResult, errs *[]error) {
	if r.Sessions == nil {
		return
	}
	sessions, err := r.Sessions.ListByUser(ctx, localUserID)
	if err != nil {
		*errs = append(*errs, err)
		return
	}
	for _, s := range sessions {
		if derr := r.Sessions.Destroy(ctx, s.ID); derr != nil {
			*errs = append(*errs, derr)
			continue
		}
		res.SessionsDestroyed++
	}
}

// revokeTrustedDeviceLeg revokes every trusted-device MFA-skip grant for
// localUserID. No-op when the leg isn't wired (WithTrustedDeviceRevocation).
func (r *StoreRevoker) revokeTrustedDeviceLeg(ctx context.Context, localUserID string, res *RevocationResult, errs *[]error) {
	if r.TrustedDevices == nil {
		return
	}
	n, err := r.TrustedDevices.RevokeAll(ctx, localUserID)
	if err != nil {
		*errs = append(*errs, err)
		return
	}
	res.TrustedDevicesRevoked = n
}

// userProviderResolver is the default SubjectResolver: it maps a SET
// subject to a local user id via core.UserProvider, with the precision the
// receiver's threat model demands (an unknown subject returns ok=false, NOT
// a guess).
//
//   - SubjectMapOpaque: the sub_id `id` (or a bare top-level `sub`) is the
//     LOCAL user id. GetByID confirms the user EXISTS; an unknown id is
//     ok=false. This is the inverse of THIS project's transmitter, which
//     emits {format:"opaque", id:<local subject>}. NOTE the trust model:
//     opaque grants the trusted transmitter authority to revoke ANY local
//     user it can name by id (a full-namespace "logout everywhere"
//     primitive — the only guard is that the user EXISTS, which an attacker
//     can satisfy with any victim's id). Use it ONLY for a FULLY-trusted
//     peer that shares this server's subject namespace; for a partially-
//     trusted upstream IdP use iss_sub (now provider-pinned), which confines
//     a transmitter to subjects under ITS operator-configured federation
//     namespace.
//   - SubjectMapIssSub: the sub_id {iss, sub} is the upstream identity.
//     GetByExternalID(provider, sub) resolves the FEDERATION LINK. The
//     provider is the OPERATOR-PINNED per-transmitter Provider (REQUIRED in
//     iss_sub mode) — it is NEVER derived from the SET's attacker-controlled
//     sub_id.iss. A subject with no such link is ok=false.
//
// A transient store error (NOT a "no such user") is returned as err so the
// receiver fails closed (no action) and the transmitter can retry.
type userProviderResolver struct {
	users core.UserProvider
}

func (u *userProviderResolver) ResolveLocalSubject(ctx context.Context, mode SubjectMapMode, provider string, sub setSubjectID) (string, bool, error) {
	switch mode {
	case SubjectMapIssSub:
		return u.resolveIssSub(ctx, provider, sub)
	default: // SubjectMapOpaque
		return u.resolveOpaque(ctx, sub)
	}
}

// resolveIssSub maps an iss_sub-shaped subject to a local user via the
// federation link, applying the four security guards IN ORDER before the
// lookup. Order is load-bearing: each guard is a separate gate and the
// no-match (ok=false) outcomes must be indistinguishable.
func (u *userProviderResolver) resolveIssSub(ctx context.Context, provider string, sub setSubjectID) (string, bool, error) {
	// Only an iss_sub-shaped (or implicitly iss_sub) subject maps here.
	// A format mismatch (e.g. the SET sent opaque to an iss_sub
	// transmitter) is NOT a match — refuse to guess.
	if sub.Format != "" && sub.Format != subjectFormatIssSub {
		return "", false, nil
	}
	if sub.Sub == "" {
		return "", false, nil
	}
	// The provider MUST be the operator-pinned per-transmitter Provider —
	// NEVER the SET's sub_id.iss. NewReceiver requires a non-empty provider
	// in iss_sub mode, so an empty one here is a programming/wiring bug, not
	// an attacker-controlled fallback. Deriving the provider from sub.Iss
	// would let a trusted (or key-compromised) transmitter name ANY other
	// provider in its sub_id and revoke users federated from a DIFFERENT
	// upstream — a cross-IdP subject hijack (targeted DoS). The
	// per-transmitter namespace isolation iss_sub exists for depends on the
	// provider being operator-pinned to THIS transmitter's federated
	// namespace.
	if provider == "" {
		return "", false, nil
	}
	// Defense-in-depth: if the SET pins a sub_id.iss, it MUST equal the
	// operator-configured provider. A sub_id.iss naming a FOREIGN provider
	// means the SET addresses a subject from a namespace this transmitter
	// is NOT trusted for → no-op (ack, no revocation). A transmitter may
	// legitimately OMIT sub_id.iss (sub.Iss == "") or set it == its
	// configured provider; only a present-and-mismatched iss is refused.
	if sub.Iss != "" && sub.Iss != provider {
		return "", false, nil
	}
	usr, err := u.users.GetByExternalID(ctx, provider, sub.Sub)
	return resolveResult(usr, err)
}

// resolveOpaque maps an opaque subject (the id, or a bare `sub` folded into
// ID by subjectID()) directly to a local user id.
func (u *userProviderResolver) resolveOpaque(ctx context.Context, sub setSubjectID) (string, bool, error) {
	// The opaque id (or a bare `sub` folded into ID by subjectID()) is
	// the local user id. Reject an iss_sub-shaped subject under opaque
	// mode (format mismatch ⇒ no guess).
	if sub.Format != "" && sub.Format != subjectFormatOpaque {
		return "", false, nil
	}
	if sub.ID == "" {
		return "", false, nil
	}
	usr, err := u.users.GetByID(ctx, sub.ID)
	return resolveResult(usr, err)
}

// resolveResult collapses a UserProvider lookup into the resolver contract:
// a found user → (id, true, nil); a "no such user" → ("", false, nil), the
// no-op case (NOT an error, NOT a guess); any other error → propagate (the
// receiver fails closed). It distinguishes "definitively absent" from "the
// store is unavailable" via core.ErrNoSuchUser so a store outage never
// silently drops a real revocation as if the subject didn't exist.
func resolveResult(usr *core.User, err error) (string, bool, error) {
	if err != nil {
		if errors.Is(err, core.ErrNoSuchUser) {
			return "", false, nil // definitively unknown ⇒ no-op + ack
		}
		return "", false, err // transient ⇒ fail closed, retry
	}
	if usr == nil || usr.ID == "" {
		return "", false, nil
	}
	return usr.ID, true, nil
}

// compile-time guards.
var (
	_ SubjectRevoker  = (*StoreRevoker)(nil)
	_ SubjectResolver = (*userProviderResolver)(nil)
)
