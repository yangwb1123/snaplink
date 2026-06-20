package snapshot

import "github.com/snaplink/sso/interfaces/sso"

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
// credential-bearing field on every client in the snapshot:
//
//   - Client.Secret — the client_secret used on the /token endpoint.
//   - Client.RegistrationAccessToken — the RFC 7592 management bearer.
//
// It deliberately leaves all NON-secret material intact: client ID,
// name, redirect URIs, scopes, and the public JWKS verification keys
// (zeroing those would defeat the inspection use case the redaction
// exists for). Users carry no credential field in this data model, so
// they are untouched.
//
// Deterministic and allocation-light: it only walks the existing client
// slice and writes empty strings into two scalar fields per client; it
// allocates nothing.
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
	})
}

// redactClientSecrets zeros the credential fields on a single client.
// Split out so the deep-copy + redact step in Export can share the exact
// same field list — adding a new secret field means touching one place.
func redactClientSecrets(c *sso.Client) {
	c.Secret = ""
	c.RegistrationAccessToken = ""
}
