package snapshot

import (
	"context"
	"errors"
	"fmt"

	gw "github.com/go-webauthn/webauthn/webauthn"
	"github.com/yangwb1123/snaplink/domains/authenticators/webauthn"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func (r *Restorer) stageClients(ctx context.Context, snap *Snapshot, opts RestoreOptions, sess *restoreSession) (CategoryCounts, error) {
	var c CategoryCounts
	if r.Clients == nil || len(snap.Resources.Clients) == 0 && opts.Mode != ModeReplace {
		return c, nil
	}

	for _, cl := range snap.Resources.Clients {
		switch opts.Mode {
		case ModeMerge:
			if err := r.mergeClient(ctx, cl, opts.DryRun, &c, sess); err != nil {
				return c, err
			}
		case ModeOverwrite, ModeReplace:
			if err := r.upsertClient(ctx, cl, opts.DryRun, &c, sess); err != nil {
				return c, err
			}
		}
	}
	return c, nil
}

// pruneClients deletes destination clients absent from the snapshot
// (ModeReplace, Phase B). The snapshot's IDs form the keep-set.
func (r *Restorer) pruneClients(ctx context.Context, snap *Snapshot, dryRun bool) (CategoryCounts, error) {
	var c CategoryCounts
	existing, err := r.Clients.List(ctx)
	if err != nil {
		return c, fmt.Errorf("list before replace: %w", err)
	}
	keep := make(map[string]bool, len(snap.Resources.Clients))
	for _, x := range snap.Resources.Clients {
		keep[x.ID] = true
	}
	for _, x := range existing {
		if keep[x.ID] {
			continue
		}
		c.Deleted++
		if !dryRun {
			if err := r.Clients.Delete(ctx, x.ID); err != nil {
				return c, fmt.Errorf("delete %q: %w", x.ID, err)
			}
		}
	}
	return c, nil
}

// mergeClient inserts cl only when absent; existing clients are left
// untouched (ModeMerge). A client this restore actually inserted is then
// run through the fresh-node secret-regeneration reconciliation — the
// write-set guard in restoreSession is what keeps a PRE-EXISTING broken
// destination client out of the rotation path ("leave existing untouched"
// stays intact).
func (r *Restorer) mergeClient(ctx context.Context, cl *sso.Client, dryRun bool, c *CategoryCounts, sess *restoreSession) error {
	if dryRun {
		if _, present := r.probeClient(ctx, cl.ID); present {
			c.Skipped++
		} else {
			c.Inserted++
			r.predictClientRotation(cl, nil, c)
		}
		return nil
	}
	err := r.Clients.Add(ctx, cl)
	if err == nil {
		c.Inserted++
		sess.writtenClients[cl.ID] = true
		r.reconcileClientRotation(ctx, cl.ID, c, sess)
	} else if errors.Is(err, sso.ErrClientExists) {
		c.Skipped++
	} else {
		return fmt.Errorf("add %q: %w", cl.ID, err)
	}
	return nil
}

// upsertClient inserts cl, or updates it when it already exists
// (ModeOverwrite / ModeReplace), preserving live credentials the
// snapshot can't carry. Every snapshot client is written in these modes,
// so all of them enter the rotation reconciliation — a client whose live
// record already carries a secret (preserved by the upsert) is simply not
// eligible.
func (r *Restorer) upsertClient(ctx context.Context, cl *sso.Client, dryRun bool, c *CategoryCounts, sess *restoreSession) error {
	if dryRun {
		live, present := r.probeClient(ctx, cl.ID)
		if present {
			c.Updated++
			r.predictClientRotation(cl, live, c)
		} else {
			c.Inserted++
			r.predictClientRotation(cl, nil, c)
		}
		return nil
	}
	err := r.Clients.Add(ctx, cl)
	if err == nil {
		c.Inserted++
		sess.writtenClients[cl.ID] = true
		r.reconcileClientRotation(ctx, cl.ID, c, sess)
		return nil
	}
	if !errors.Is(err, sso.ErrClientExists) {
		return fmt.Errorf("add %q: %w", cl.ID, err)
	}
	// Client.Secret + RegistrationAccessToken are json:"-", so a
	// serialized snapshot never carries them. A wholesale Update
	// with the empty incoming values would destroy the live
	// hashed credentials — preserve them from the existing record
	// when the snapshot omits them.
	upd, err := r.preserveClientSecrets(ctx, cl)
	if err != nil {
		return fmt.Errorf("update %q: %w", cl.ID, err)
	}
	if err := r.Clients.Update(ctx, upd); err != nil {
		return fmt.Errorf("update %q: %w", cl.ID, err)
	}
	c.Updated++
	sess.writtenClients[cl.ID] = true
	r.reconcileClientRotation(ctx, cl.ID, c, sess)
	return nil
}

// probeClient mirrors the apply path's presence probe: any Get error
// counts as absent (the same shape the pre-existing dry-run used — a
// transient backend failure predicts "would insert" exactly as before).
func (r *Restorer) probeClient(ctx context.Context, id string) (*sso.Client, bool) {
	live, err := r.Clients.Get(ctx, id)
	if err != nil {
		return nil, false
	}
	return live, true
}

// secretAuthClient reports whether the client authenticates with a shared
// secret (RFC 6749 §2.3.1): the empty method is the client_secret_basic
// default, and federation-derived clients use vouched JWKS — never a
// secret. Public ("none") and asymmetric/certificate clients are excluded
// so the rotation never mints spurious secrets for clients that must not
// hold one.
func secretAuthClient(cl *sso.Client) bool {
	if cl == nil || cl.Federation {
		return false
	}
	switch cl.TokenEndpointAuthMethod {
	case "", "client_secret_basic", "client_secret_post":
		return true
	default:
		return false
	}
}

// predictClientRotation is the dry-run half of the Decision-1
// reconciliation: it predicts RequiresRotation with the exact decision the
// real run makes, so the preview never lies. live is the pre-write live
// record (nil when the client would be INSERTED, whose post-write secret is
// therefore empty); a present client's live secret is what the upsert
// preserves, so a non-empty one means the client ends up with credentials
// and needs nothing. Both active (would rotate) and inactive (flag-on-
// enable) secret-auth clients count — matching reconcileClientRotation.
func (r *Restorer) predictClientRotation(cl *sso.Client, live *sso.Client, c *CategoryCounts) {
	if !secretAuthClient(cl) {
		return
	}
	if live != nil && live.Secret != "" {
		return
	}
	c.RequiresRotation++
}

// reconcileClientRotation runs Decision 1's fresh-node secret regeneration
// for one client this restore just wrote. The POST-WRITE live record
// decides eligibility (the snapshot never carries a secret, so the live
// record is the only honest source): secret-auth, Active, and empty
// post-write secret. Rotation failures never abort the plan — they are
// recorded in Report.Errors while the loop continues with the next client,
// and the client stays counted in RequiresRotation so the backlog is
// visible. Rotation happens INSIDE the clients stage, i.e. before
// InvalidateRestoredControlPlane(), whose full control-plane invalidation
// covers the rotated secrets (no new invalidation mechanism needed).
func (r *Restorer) reconcileClientRotation(ctx context.Context, clientID string, c *CategoryCounts, sess *restoreSession) {
	live, err := r.Clients.Get(ctx, clientID)
	if err != nil {
		sess.reportError(CategoryClients, fmt.Errorf("read back %q after write: %w", clientID, err))
		c.RequiresRotation++
		return
	}
	if !secretAuthClient(live) || live.Secret != "" {
		return
	}
	if !live.Active {
		// The Active gate (per the requirement) skips rotation for
		// disabled clients, which stay secret-less and would STAY
		// secret-less when later enabled — a latent trap. The report
		// counts them (flag-on-enable) so operators re-enabling a client
		// rotate it first; see the dr-framework runbook.
		c.RequiresRotation++
		return
	}
	rotator, ok := r.Clients.(SecretRotator)
	if !ok {
		c.RequiresRotation++
		return
	}
	secret, err := rotator.RotateSecret(ctx, clientID)
	if err != nil {
		sess.reportError(CategoryClients, fmt.Errorf("rotate secret %q: %w", clientID, err))
		c.RequiresRotation++
		return
	}
	// RPC-response-only value: audit and operations records must strip
	// the secret (see RedactCredentialRecovery).
	sess.rep.CredentialRecovery = append(sess.rep.CredentialRecovery, CredentialRecovery{ClientID: clientID, Secret: secret})
}

// preserveClientSecrets returns cl with its Secret and
// RegistrationAccessToken backfilled from the live store whenever the
// incoming (snapshot-sourced) values are empty. Because both fields are
// json:"-", a deserialized snapshot always omits them; restoring without
// this would overwrite live credentials with empty strings. The returned
// value is a copy so the snapshot's in-memory client is left untouched
// (a caller may reuse the snapshot). When neither field needs
// backfilling the original cl is returned unchanged.
func (r *Restorer) preserveClientSecrets(ctx context.Context, cl *sso.Client) (*sso.Client, error) {
	if cl == nil || (cl.Secret != "" && cl.RegistrationAccessToken != "") {
		return cl, nil
	}
	existing, err := r.Clients.Get(ctx, cl.ID)
	if err != nil {
		// No live record to carry credentials from (e.g. deleted between
		// the ErrClientExists probe and here): nothing to preserve.
		if errors.Is(err, sso.ErrNoSuchClient) {
			return cl, nil
		}
		return nil, err
	}
	out := *cl
	if out.Secret == "" {
		out.Secret = existing.Secret
	}
	if out.RegistrationAccessToken == "" {
		out.RegistrationAccessToken = existing.RegistrationAccessToken
	}
	return &out, nil
}

func (r *Restorer) stageUsers(ctx context.Context, snap *Snapshot, opts RestoreOptions) (CategoryCounts, error) {
	var c CategoryCounts
	if r.Users == nil || len(snap.Resources.Users) == 0 && opts.Mode != ModeReplace {
		return c, nil
	}

	for _, u := range snap.Resources.Users {
		switch opts.Mode {
		case ModeMerge:
			if err := r.mergeUser(ctx, u, opts.DryRun, &c); err != nil {
				return c, err
			}
		case ModeOverwrite, ModeReplace:
			if err := r.upsertUser(ctx, u, opts.DryRun, &c); err != nil {
				return c, err
			}
		}
	}
	return c, nil
}

// pruneUsers deletes destination users absent from the snapshot
// (ModeReplace, Phase B).
func (r *Restorer) pruneUsers(ctx context.Context, snap *Snapshot, dryRun bool) (CategoryCounts, error) {
	var c CategoryCounts
	existing, err := r.Users.List(ctx)
	if err != nil {
		return c, fmt.Errorf("list before replace: %w", err)
	}
	keep := make(map[string]bool, len(snap.Resources.Users))
	for _, u := range snap.Resources.Users {
		keep[u.ID] = true
	}
	for _, u := range existing {
		if keep[u.ID] {
			continue
		}
		if !dryRun {
			if err := r.Users.Delete(ctx, u.ID); err != nil {
				return c, fmt.Errorf("delete %q: %w", u.ID, err)
			}
		}
		c.Deleted++
	}
	return c, nil
}

// mergeUser inserts u only when absent (ModeMerge).
func (r *Restorer) mergeUser(ctx context.Context, u *sso.User, dryRun bool, c *CategoryCounts) error {
	present, err := r.userPresent(ctx, u.ID)
	if err != nil {
		return err
	}
	if present {
		c.Skipped++
		return nil
	}
	if !dryRun {
		if err := r.Users.CreateOrUpdate(ctx, u); err != nil {
			return fmt.Errorf("create %q: %w", u.ID, err)
		}
	}
	c.Inserted++
	return nil
}

// upsertUser inserts or updates u (ModeOverwrite / ModeReplace).
func (r *Restorer) upsertUser(ctx context.Context, u *sso.User, dryRun bool, c *CategoryCounts) error {
	present, err := r.userPresent(ctx, u.ID)
	if err != nil {
		return err
	}
	if !dryRun {
		if err := r.Users.CreateOrUpdate(ctx, u); err != nil {
			return fmt.Errorf("upsert %q: %w", u.ID, err)
		}
	}
	if present {
		c.Updated++
	} else {
		c.Inserted++
	}
	return nil
}

// userPresent reports whether a user with id exists in the destination.
// ErrNoSuchUser maps to absent; any other error (a transient backend
// failure — connection reset, timeout) propagates instead of being
// silently treated as "doesn't exist." Without this distinction a
// transient GetByID failure during ModeMerge would fall through to
// CreateOrUpdate and clobber a live user's data with the snapshot's
// stale copy — exactly the destructive behavior ModeMerge promises not
// to do ("leave existing untouched").
func (r *Restorer) userPresent(ctx context.Context, id string) (bool, error) {
	if _, err := r.Users.GetByID(ctx, id); err == nil {
		return true, nil
	} else if !errors.Is(err, sso.ErrNoSuchUser) {
		return false, fmt.Errorf("get %q: %w", id, err)
	}
	return false, nil
}

// stageWebAuthn replays the v3 passkey-portability category. Semantics:
//
//   - The category runs AFTER users (stagePlan order) — passkeys key on
//     restored identities. A record whose username is absent from the
//     snapshot's users category is an orphan: skipped + counted (identity
//     is the users category's job).
//   - Unknown user ⇒ created with the exported handle via the optional
//     webauthn.HandlePreservingUserCreator. Absent capability ⇒ the record
//     is SKIPPED + counted, never silently re-minted: a re-minted handle
//     strands discoverable/conditional login (the authenticator presents
//     the old handle; GetByHandle misses), so fail-closed is the honest
//     outcome.
//   - Credential ID unknown ⇒ AddCredential (insert). Present ⇒ compare
//     counters: live newer ⇒ skip + count (never write the counter
//     backwards — the production-clocks-slew discipline); otherwise
//     UpdateCredential (converge; equal counts as updated, matching the
//     upsert-counting convention elsewhere).
//   - Extension metadata replays through the optional
//     webauthn.CredentialExtensionSetter; absent ⇒ silently nil
//     ("unknown"), the documented safe default.
//   - NO prune in Phase B by decision: replace-restore converges but never
//     wipes credentials — the destination is the authority on credentials
//     enrolled after the snapshot was taken, and the counter-regression
//     guard already prevents backwards overwrites. Counts make the
//     additive behavior observable.
//
// Dry-run performs the identical probes with zero writes.
func (r *Restorer) stageWebAuthn(ctx context.Context, snap *Snapshot, opts RestoreOptions) (CategoryCounts, error) {
	var counts CategoryCounts
	if r.WebAuthn == nil || len(snap.Resources.WebAuthnCredentials) == 0 {
		return counts, nil
	}
	// Identity ownership: the users category decides which webauthn
	// records are restorable. Keyed by sso.User.ID — the stock binary's
	// webauthn username is the subject ID (MFAEnrollmentAdapter).
	restoredUsers := make(map[string]bool, len(snap.Resources.Users))
	for _, u := range snap.Resources.Users {
		if u != nil {
			restoredUsers[u.ID] = true
		}
	}
	handleCreator, _ := r.WebAuthn.(webauthn.HandlePreservingUserCreator)
	extSetter, _ := r.WebAuthn.(webauthn.CredentialExtensionSetter)

	for _, rec := range snap.Resources.WebAuthnCredentials {
		if !restoredUsers[rec.UserName] {
			// Orphan record: the users category owns identity.
			counts.Skipped++
			continue
		}
		user, err := r.WebAuthn.GetByName(ctx, rec.UserName)
		switch {
		case err == nil:
			// Existing webauthn user: credentials converge below.
		case errors.Is(err, webauthn.ErrUserUnknown):
			if handleCreator == nil {
				// Fail-closed: without handle preservation a re-minted
				// handle breaks discoverable/conditional login. Counted,
				// never silently dropped.
				counts.Skipped++
				continue
			}
			if !opts.DryRun {
				if _, err := handleCreator.CreateUserWithHandle(ctx, rec.UserName, rec.DisplayName, rec.Handle); err != nil {
					return counts, fmt.Errorf("create webauthn user %q: %w", rec.UserName, err)
				}
			}
		default:
			return counts, fmt.Errorf("get webauthn user %q: %w", rec.UserName, err)
		}
		if err := r.replayWebAuthnCredential(ctx, user, rec, opts.DryRun, &counts, extSetter); err != nil {
			return counts, err
		}
	}
	return counts, nil
}

// replayWebAuthnCredential applies one credential to an existing (or just
// created) webauthn user: insert, converge, or counter-regression skip.
func (r *Restorer) replayWebAuthnCredential(
	ctx context.Context, user *webauthn.User, rec webauthn.UserCredentialRecord,
	dryRun bool, counts *CategoryCounts, extSetter webauthn.CredentialExtensionSetter,
) error {
	live := findCredential(user, rec.Credential.ID)
	switch {
	case live == nil:
		if !dryRun {
			if err := r.WebAuthn.AddCredential(ctx, rec.UserName, &rec.Credential); err != nil {
				return fmt.Errorf("add webauthn credential for %q: %w", rec.UserName, err)
			}
			if err := replayCredentialExtensions(ctx, extSetter, rec, &rec.Credential); err != nil {
				return err
			}
		}
		counts.Inserted++
	case live.Authenticator.SignCount > rec.Credential.Authenticator.SignCount:
		// Fail-closed: live is newer — never write the counter backwards.
		counts.Skipped++
	default:
		if !dryRun {
			if err := r.WebAuthn.UpdateCredential(ctx, rec.UserName, &rec.Credential); err != nil {
				return fmt.Errorf("update webauthn credential for %q: %w", rec.UserName, err)
			}
			if err := replayCredentialExtensions(ctx, extSetter, rec, &rec.Credential); err != nil {
				return err
			}
		}
		counts.Updated++
	}
	return nil
}

func extensionsPresent(ext webauthn.CredentialExtensions) bool {
	return ext.Discoverable != nil || ext.LargeBlobSupported != nil
}

// findCredential locates the live credential with ID, or nil.
func findCredential(user *webauthn.User, id []byte) *gw.Credential {
	if user == nil {
		return nil
	}
	for i := range user.Credentials {
		if bytesEqualSlices(user.Credentials[i].ID, id) {
			return &user.Credentials[i]
		}
	}
	return nil
}
