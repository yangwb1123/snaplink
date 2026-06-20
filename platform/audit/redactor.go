package audit

import (
	"crypto/sha256"
	"encoding/base64"
	"net"
	"strings"
)

// Redactor strips or transforms PII on an Event BEFORE the Sink
// sees it. Use cases:
//
//   - GDPR-style "no raw email/phone in audit logs"
//   - SOC 2 audit-log retention requirements that demand
//     pseudonymized identifiers
//   - Right-to-be-forgotten (RTBF) post-processing: replace
//     identifiers with stable opaque pseudonyms so audit history
//     is preservable without re-identifying the subject
//
// Contract: Redact MAY mutate the event in place. The Recorder
// invokes it BEFORE the hash chainer (when wired) so the hash
// is computed over the redacted form — a downstream verifier
// validates the chain against what was actually stored, never
// the pre-redaction values.
//
// Composition: most deployments want several rules layered
// (ActorID hash + IP truncate + UA strip + named metadata
// keys). Use Compose to chain them in deterministic order.
type Redactor interface {
	Redact(e *Event)
}

// RedactorFunc adapts a plain function into a Redactor.
type RedactorFunc func(*Event)

// Redact implements the Redactor interface.
func (f RedactorFunc) Redact(e *Event) { f(e) }

// Compose returns a Redactor that applies each supplied
// Redactor in order. Empty input is the no-op redactor.
func Compose(redactors ...Redactor) Redactor {
	switch len(redactors) {
	case 0:
		return RedactorFunc(func(*Event) {})
	case 1:
		return redactors[0]
	}
	return RedactorFunc(func(e *Event) {
		for _, r := range redactors {
			r.Redact(e)
		}
	})
}

// RedactActorIDHash returns a Redactor that replaces
// `e.ActorID` with `sha256(salt + ":" + actorID)[:16]` encoded
// as base64url. The salt is REQUIRED (a missing salt makes the
// hash trivially reversible via a rainbow table of common user
// IDs). Empty ActorID is left untouched.
//
// The replacement is short (16-byte digest, 22-char base64) so
// audit dashboards stay readable; collision risk at this length
// is negligible at any realistic actor cardinality.
func RedactActorIDHash(salt string) Redactor {
	return RedactorFunc(func(e *Event) {
		if e.ActorID == "" {
			return
		}
		e.ActorID = "h:" + hashActor(salt, e.ActorID)
	})
}

// hashActor is the internal hash helper. Exported as a leading-
// "h:" prefix on the replacement makes pseudonymous IDs visually
// distinguishable from raw ones — operators can spot-check that
// redaction is actually firing.
func hashActor(salt, actorID string) string {
	sum := sha256.Sum256([]byte(salt + ":" + actorID))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// RedactIPTruncate returns a Redactor that truncates
// `e.ActorIP` to /24 for IPv4 and /48 for IPv6 — preserves
// geo-region utility (an attacker IP shows up in roughly the
// same /24 across attempts) while shedding the
// per-customer-identifiable last octets. Invalid IPs are
// passed through unchanged so a misconfigured upstream proxy
// doesn't silently zero out the field.
func RedactIPTruncate() Redactor {
	return RedactorFunc(func(e *Event) {
		if e.ActorIP == "" {
			return
		}
		ip := net.ParseIP(e.ActorIP)
		if ip == nil {
			return
		}
		if v4 := ip.To4(); v4 != nil {
			mask := net.CIDRMask(24, 32)
			masked := v4.Mask(mask)
			e.ActorIP = masked.String() + "/24"
			return
		}
		// IPv6 — truncate to /48 (RIRs typically allocate at
		// this prefix length, so the geo + ASN signal stays).
		mask := net.CIDRMask(48, 128)
		masked := ip.Mask(mask)
		e.ActorIP = masked.String() + "/48"
	})
}

// RedactUserAgent returns a Redactor that clears the
// `UserAgent` field. UA strings are heavily fingerprintable
// (browser version + OS + extensions); for compliance, just
// blank them. Operators who need fraud-detection on UAs
// should layer their own hash-redactor instead.
func RedactUserAgent() Redactor {
	return RedactorFunc(func(e *Event) {
		e.UserAgent = ""
	})
}

// RedactMetadataKeys returns a Redactor that deletes the listed
// keys from `e.Metadata`. Use for known-sensitive keys (email,
// phone, target) without disturbing the rest of the metadata
// surface. Case-sensitive — match the keys exactly as written.
func RedactMetadataKeys(keys ...string) Redactor {
	return RedactorFunc(func(e *Event) {
		if e.Metadata == nil {
			return
		}
		for _, k := range keys {
			delete(e.Metadata, k)
		}
	})
}

// RedactMetadataKeyPrefixes returns a Redactor that deletes
// every metadata key whose name starts with any of the supplied
// prefixes. Useful for "everything under pii.*" patterns.
func RedactMetadataKeyPrefixes(prefixes ...string) Redactor {
	return RedactorFunc(func(e *Event) {
		if e.Metadata == nil || len(prefixes) == 0 {
			return
		}
		for k := range e.Metadata {
			for _, p := range prefixes {
				if strings.HasPrefix(k, p) {
					delete(e.Metadata, k)
					break
				}
			}
		}
	})
}

// DefaultPIIRedactor returns a Compose of the conservative
// always-on redactions: ActorID hashed with the supplied salt,
// IP truncated, UA stripped. Per-deployment additions (specific
// metadata keys, custom transformers) should layer with Compose.
//
// salt MUST be a deployment-stable, secret value — leaking it
// re-enables the hash inversion attack. Recommended source: an
// env-var loaded into the bootstrap config, NOT a literal
// committed to source.
func DefaultPIIRedactor(salt string) Redactor {
	return Compose(
		RedactActorIDHash(salt),
		RedactIPTruncate(),
		RedactUserAgent(),
	)
}

// WithRedactor wires a Redactor into the Recorder. Applied
// BEFORE the hash chainer so the chain validates over the
// redacted form (no leak via "what was the pre-redaction
// value of this hashed event"). Multiple calls overwrite —
// compose policies with the Compose helper instead.
func WithRedactor(r Redactor) Option {
	return func(rec *Recorder) { rec.redactor = r }
}
