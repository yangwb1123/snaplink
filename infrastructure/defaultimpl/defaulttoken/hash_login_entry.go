package defaulttoken

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/yangwb1123/snaplink/domains/anomaly"
)

// HashLoginEntry builds a [anomaly.LoginEntry] from a [anomaly.LoginEvent]
// + an IP salt + a per-subject UA salt. The canonical helper —
// detector implementations call this rather than reaching for
// crypto/sha256 themselves, so the hash schema stays uniform
// across detectors + future store backends.
//
// ipSalt is a deployment-stable secret (operator-provided; rotates
// alongside the per-deployment audit redactor salt). uaSubjectSalt
// is per-subject so a captured UA hash doesn't correlate across
// users — typically derived deterministically from subjectID +
// ipSalt: `sha256(subjectID || ipSalt)[:8]`.
//
// Returns nil + empty error when event.SubjectID is empty
// (anonymous failure that detectors should skip).
func HashLoginEntry(event *anomaly.LoginEvent, ipSalt []byte) *anomaly.LoginEntry {
	if event == nil || event.SubjectID == "" {
		return nil
	}
	uaSubjectSalt := deriveUASubjectSalt(event.SubjectID, ipSalt)
	entry := &anomaly.LoginEntry{
		SubjectID: event.SubjectID,
		ClientID:  event.ClientID,
		Outcome:   event.Outcome,
		IPHash:    hashIP(event.RemoteIP, ipSalt),
		Timestamp: event.Timestamp,
	}
	if event.Geo != nil {
		entry.CountryCode = event.Geo.CountryCode
		entry.Latitude = event.Geo.Latitude
		entry.Longitude = event.Geo.Longitude
	}
	if event.UserAgent != "" {
		entry.UAFingerprintHash = hashUA(event.UserAgent, uaSubjectSalt)
	}
	return entry
}

// hashIP produces a salted 16-hex (64-bit) IP fingerprint. Truncated
// to keep the storage column narrow + fingerprint short enough not
// to become a strong identifier by itself. Salted so cross-deploy
// linkage requires the salt.
func hashIP(ip string, salt []byte) string {
	if ip == "" {
		return ""
	}
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(ip))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

// hashUA produces a per-subject-salted 16-hex (64-bit) UA
// fingerprint. The per-subject salt is the GDPR-friendly choice:
// even if the operator's audit log is dumped, captured UA hashes
// don't correlate device usage across users.
func hashUA(ua string, subjectSalt []byte) string {
	if ua == "" {
		return ""
	}
	h := sha256.New()
	h.Write(subjectSalt)
	h.Write([]byte(ua))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

// deriveUASubjectSalt deterministically derives a per-subject salt
// from subjectID + the deployment ipSalt. Deterministic so detectors
// can re-derive on read; mixed with deployment salt so two
// deployments don't reuse the same per-subject salt for the same
// subjectID (cross-deployment correlation defeated).
func deriveUASubjectSalt(subjectID string, ipSalt []byte) []byte {
	h := sha256.New()
	h.Write(ipSalt)
	h.Write([]byte(":ua:"))
	h.Write([]byte(subjectID))
	sum := h.Sum(nil)
	return sum[:16]
}
