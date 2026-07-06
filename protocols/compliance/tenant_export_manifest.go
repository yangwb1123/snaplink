package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// TenantExportManifest is the bundle's self-describing footer: a per-section
// item count (for a quick "did I get everything" glance without parsing the
// whole payload) and a content checksum an admin can use to confirm a
// downloaded bundle matches what was generated — the bundle-level analogue
// of auditexport.ExportBundle's boundary/head hash, since a tenant export
// has no hash CHAIN to anchor against (unlike the audit log).
type TenantExportManifest struct {
	Sections map[string]int `json:"sections"`
	Checksum string         `json:"checksum"`
}

// buildTenantExportManifest computes exp's manifest. Called once, last, by
// BuildTenantExport after every section is populated.
func buildTenantExportManifest(exp *TenantExport) TenantExportManifest {
	return TenantExportManifest{
		Sections: tenantExportSectionCounts(exp),
		Checksum: tenantExportChecksum(exp),
	}
}

// tenantExportSectionCounts summarizes each section's item count. "sessions"
// and "audit_events" come from their summary structs' Total (there is no
// per-item slice for those sections — see TenantSessionsSummary /
// audit.Facets) rather than a slice length; audit_events is omitted
// entirely when no audit summary was available (distinguishing "zero
// events" from "couldn't ask", matching TenantExport.AuditSummary's nil
// contract).
func tenantExportSectionCounts(exp *TenantExport) map[string]int {
	counts := map[string]int{
		"clients":     len(exp.Clients),
		"members":     len(exp.Members),
		"users":       len(exp.Users),
		"invitations": len(exp.Invitations),
		"connections": len(exp.Connections),
		"roles":       len(exp.Roles),
		"assignments": len(exp.Assignments),
		"sessions":    exp.SessionsSummary.Total,
	}
	if exp.AuditSummary != nil {
		counts["audit_events"] = exp.AuditSummary.Total
	}
	return counts
}

// tenantExportChecksum hashes exp's data payload (everything except
// Manifest, which doesn't exist yet at the point BuildTenantExport calls
// this). It is computed once over the SAME *TenantExport object the caller
// just assembled, so the checksum is self-consistent for the life of that
// bundle — NOT a cross-run content hash: the memory-backed stores this
// package composes iterate a Go map internally, so re-running
// BuildTenantExport against identical underlying data can legitimately
// yield a different slice order (and therefore a different checksum) on a
// second call. That is fine for this checksum's purpose — confirming a
// downloaded bundle wasn't corrupted/tampered after generation — which only
// ever compares a bundle against itself.
func tenantExportChecksum(exp *TenantExport) string {
	cp := *exp
	cp.Manifest = TenantExportManifest{}
	raw, err := json.Marshal(cp)
	if err != nil {
		// The bundle's field types (structs/slices/maps/strings/times) can't
		// fail to marshal — a non-nil err here would be a programming error
		// (e.g. a future field of an unsupported type), not an operator
		// condition, so there is nothing actionable to surface upward.
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// VerifyTenantExport recomputes exp's checksum and compares it against
// exp.Manifest.Checksum — for a DOWNSTREAM recipient (an admin who saved the
// downloaded JSON bundle) to confirm it is exactly what BuildTenantExport
// produced, mirroring auditexport.VerifyExportBundle's role for that bundle
// shape.
func VerifyTenantExport(exp *TenantExport) error {
	if exp == nil {
		return errors.New("compliance: nil tenant export")
	}
	if got, want := tenantExportChecksum(exp), exp.Manifest.Checksum; got != want {
		return fmt.Errorf("compliance: tenant export checksum mismatch: got %s want %s", got, want)
	}
	return nil
}
