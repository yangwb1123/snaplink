package snapshot

import "github.com/yangwb1123/snaplink/interfaces/sso"

// Redactor strips or transforms secret-bearing fields on a Snapshot
// BEFORE it is serialized + sealed. It mirrors the audit.Redactor idiom
// (same Compose pattern) so the two redaction surfaces feel identical to
// operators.
//
// Why this exists: an exported Snapshot carries the operator's full
// client set, and sso.Client holds credential material (the client
// Secret + the RFC 7592 RegistrationAccessToken). With an encryption
// Sealer wired that material is protected at rest — encryption is the
// mitigation for RESTORABLE backups. But a PLAINTEXT export
// (encryption: none) produced for inspection / sharing / debugging is a
// raw artifact an operator might forward to a peer or paste into a
// ticket. A Redactor zeros those fields so such an artifact can be
// shared without leaking live credentials.
//
// CRITICAL: a redacted snapshot is for INSPECTION / SHARING, NOT
// restore. Its clients have no Secret, so a restored copy cannot
// authenticate the client_secret grant — operators wanting a restorable
// backup MUST use an encryption Sealer instead of (or in addition to)
// redaction, and MUST NOT redact.
//
// Contract: Redact MAY mutate the Snapshot in place. It is invoked by
// Snapshotter.Export on the snapshot it is about to return; the
// snapshot's Client pointers are export-local copies (Export deep-copies
// each client before handing it to the redactor) so redaction NEVER
// touches the live ClientStore's in-memory objects.
type Redactor interface {
	Redact(snap *Snapshot)
}

// RedactorFunc adapts a plain function into a Redactor.
type RedactorFunc func(*Snapshot)

// Redact implements the Redactor interface.
func (f RedactorFunc) Redact(snap *Snapshot) { f(snap) }

// Compose returns a Redactor that applies each supplied Redactor in
// order. Empty input is the no-op redactor. Mirrors audit.Compose.
func Compose(redactors ...Redactor) Redactor {
	switch len(redactors) {
	case 0:
		return RedactorFunc(func(*Snapshot) {})
	case 1:
		return redactors[0]
	}
	return RedactorFunc(func(snap *Snapshot) {
		for _, r := range redactors {
			r.Redact(snap)
		}
	})
}

// SnapshotRedactSecrets returns a Redactor that zeros every
// credential-bearing field on every client AND user in the snapshot:
//
//   - Client.Secret — the client_secret used on the /token endpoint.
//   - Client.RegistrationAccessToken — the RFC 7592 management bearer.
//   - User.Attributes credential keys — the password_hash + format the
//     authenticator verifies against, and the bootstrap admin's generated
//     PLAINTEXT seeded_password.
//
// It deliberately leaves all NON-secret material intact: client ID, name,
// redirect URIs, scopes, the public JWKS verification keys, and a user's
// profile attributes (zeroing those would defeat the inspection use case the
// redaction exists for).
//
// LIMITATION: the user scrub is a DENYLIST of known credential keys (see
// secretUserAttrKeys), not an allowlist — the inspection use case requires
// keeping a user's arbitrary profile attributes, which an allowlist could not do.
// It covers every secret the bundled backends + bootstrap write to
// User.Attributes, but a CUSTOM backend (or an import) that stores a secret under
// a different key would NOT be scrubbed. Operators sharing a redacted snapshot
// from a custom deployment MUST verify their secret-bearing keys are listed here.
//
// SAFETY: it ONLY mutates export-local copies. Export deep-copies clients AND
// users (copyClientsForRedaction / copyUsersForRedaction) before invoking the
// redactor — that struct copy is what isolates each export user from the live
// UserProvider object. redactUserSecrets then assigns the COPY a fresh,
// secret-free Attributes map, never deleting from the shared source map, so the
// running server's user (and its password_hash) is never disturbed.
func SnapshotRedactSecrets() Redactor {
	return RedactorFunc(func(snap *Snapshot) {
		if snap == nil {
			return
		}
		for _, c := range snap.Resources.Clients {
			if c == nil {
				continue
			}
			redactClientSecrets(c)
		}
		for _, u := range snap.Resources.Users {
			if u == nil {
				continue
			}
			redactUserSecrets(u)
		}
	})
}

// redactClientSecrets zeros the credential fields on a single client.
// Split out so the deep-copy + redact step in Export can share the exact
// same field list — adding a new secret field means touching one place.
func redactClientSecrets(c *sso.Client) {
	c.Secret = ""
	c.RegistrationAccessToken = ""
}

// secretUserAttrKeys are the User.Attributes keys holding credential material:
// the password verifier's hash (+ format) and the bootstrap admin's generated
// PLAINTEXT password. Kept as literals (matching authenticators.AttrPasswordHash
// / AttrPasswordHashFormat and platform/bootstrap's seeded_password) to avoid a
// cross-layer import in this thin redactor.
var secretUserAttrKeys = []string{"password_hash", "password_hash_format", "seeded_password"}

// redactUserSecrets removes credential attribute keys from a user by ASSIGNING a
// fresh Attributes map (rather than deleting from the existing one), so the
// source MAP object shared with the export copy is never mutated. The caller
// MUST pass an export-local copy (copyUsersForRedaction): this reassigns u's
// Attributes FIELD, so on a live *sso.User it would strip password_hash and
// break login.
func redactUserSecrets(u *sso.User) {
	if len(u.Attributes) == 0 {
		return
	}
	cleaned := make(map[string]string, len(u.Attributes))
	for k, v := range u.Attributes {
		cleaned[k] = v
	}
	for _, k := range secretUserAttrKeys {
		delete(cleaned, k)
	}
	if len(cleaned) == 0 {
		cleaned = nil
	}
	u.Attributes = cleaned
}
