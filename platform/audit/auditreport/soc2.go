// Package auditreport packages a previously-built, previously-verified
// [auditexport.ExportBundle] into a SOC2-flavored evidence pack: event
// counts bucketed by illustrative Trust-Services-Criteria control area,
// plus the bundle's own chain-verification attestation and generation
// metadata.
//
// MANDATORY DISCLAIMER (also carried on every report as
// [SOC2Report.MappingDisclaimer] and printed by the CLI's help text):
// the control-area mapping in this package is an ILLUSTRATIVE, MECHANICAL
// cross-reference from audit.EventType to a commonly-cited SOC2 Trust
// Services Criterion. It is NOT a vetted SOC2 control mapping and has not
// been reviewed by qualified compliance or legal counsel. A real SOC2
// evidence submission needs that review before this artifact is used as
// actual audit evidence — this package only proves the codebase can
// MECHANICALLY produce a packaged, tamper-evident report over its own
// audit trail, not that the mapping satisfies a specific auditor.
//
// This package performs NO verification of its own — [BuildSOC2Report]
// is a pure, side-effect-free transform, and [VerifyAndBuildSOC2Report]
// delegates the tamper-evidence check to [auditexport.VerifyExportBundle]
// (which in turn reuses the platform/audit hash-chain verifiers). Never
// re-implement that check here: a SOC2 evidence pack is only as
// trustworthy as the bundle it was built from, never more.
package auditreport

import (
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/audit/auditexport"
)

// SOC2FormatVersion is the envelope format of SOC2Report; bump on
// breaking layout changes (mirrors auditexport.FormatVersion's own
// convention so a reader can distinguish a bundle-shape change from a
// report-shape change).
const SOC2FormatVersion = 1

// MappingDisclaimer is the fixed, non-configurable text stamped onto
// every SOC2Report — see the package doc for the full rationale. It is
// deliberately NOT a template or a config option: the disclaimer must
// appear verbatim on every artifact this package produces, with no way
// for an operator to omit or soften it.
const MappingDisclaimer = "This report's Trust-Services control-area mapping is an illustrative, mechanical cross-reference from audit EventType to a commonly-cited SOC2 Trust Services Criterion. It is NOT a vetted SOC2 control mapping and has not been reviewed by qualified compliance or legal counsel. Treat it as a starting point for an auditor's own analysis, not as compliance evidence on its own."

// uncategorizedCode / uncategorizedName label the catch-all bucket for
// any audit.EventType that controlAreaDefs does not claim — including
// custom, operator-defined event types (EventType's doc explicitly
// allows those). Keeping this bucket ALWAYS PRESENT (rather than
// omitted, or an error) is what keeps a report always renderable even
// as the event-type catalogue grows ahead of this package's mapping —
// see the drift test for the CI-side catch of that growth.
const (
	uncategorizedCode = "uncategorized"
	uncategorizedName = "Uncategorized"
)

// ControlArea buckets a subset of a bundle's events into one evidence
// group. For a NAMED area (from controlAreaDefs), EventTypes is that
// area's STATIC vocabulary — present even when TotalEvents is 0, so a
// report always documents which event types an area is defined to
// cover. For the Uncategorized bucket, EventTypes is instead the
// DISTINCT set of types actually OBSERVED in the bundle that matched no
// named area — there is no static vocabulary for "everything else",
// including operator-defined custom types.
//
// No raw event payloads appear here or anywhere in SOC2Report: only
// aggregated counts. The events themselves (and whatever PII/detail
// they carry) stay solely in the caller-held ExportBundle, which the
// report never re-embeds.
type ControlArea struct {
	Code           string            `json:"code"`
	Name           string            `json:"name"`
	EventTypes     []audit.EventType `json:"event_types"`
	TotalEvents    int               `json:"total_events"`
	ByOutcome      map[string]int    `json:"by_outcome,omitempty"`
	DistinctActors int               `json:"distinct_actors"`
}

// ChainAttestation carries the source bundle's tamper-evidence metadata
// WITHOUT the underlying events — see ControlArea's doc: the report
// aggregates counts and never re-embeds audit.Event values. Verified
// records the caller's PRIOR audit.VerifyExportBundle result (see
// VerifyAndBuildSOC2Report); BuildSOC2Report itself never sets it true
// on its own authority.
type ChainAttestation struct {
	Verified          bool                     `json:"verified"`
	BundleFormat      int                      `json:"bundle_format_version"`
	BundleGeneratedAt time.Time                `json:"bundle_generated_at"`
	Contiguous        bool                     `json:"contiguous"`
	BoundaryPrevHash  string                   `json:"boundary_prev_hash"`
	HeadHash          string                   `json:"head_hash,omitempty"`
	EventCount        int                      `json:"event_count"`
	Filter            auditexport.ExportFilter `json:"filter"`
}

// SOC2Report is the self-contained evidence-pack artifact: control-area
// evidence groupings plus the source bundle's chain-verification
// attestation and this report's own generation metadata.
type SOC2Report struct {
	FormatVersion     int              `json:"format_version"`
	GeneratedAt       time.Time        `json:"generated_at"`
	MappingDisclaimer string           `json:"mapping_disclaimer"`
	Chain             ChainAttestation `json:"chain"`
	ControlAreas      []ControlArea    `json:"control_areas"`
	Uncategorized     ControlArea      `json:"uncategorized"`
}

// BuildSOC2Report aggregates bundle's events into named control areas
// plus the Uncategorized catch-all. chainVerified records the caller's
// PRIOR audit.VerifyExportBundle result — this function does NOT
// re-verify (kept a pure, side-effect-free transform so it is trivial to
// unit test against synthetic bundles); see VerifyAndBuildSOC2Report for
// the fail-closed wrapper real callers use.
func BuildSOC2Report(bundle *auditexport.ExportBundle, chainVerified bool) (*SOC2Report, error) {
	if bundle == nil {
		return nil, auditexport.ErrNilBundle
	}
	areas := make([]ControlArea, len(controlAreaDefs))
	claimed := make(map[audit.EventType]int, len(controlAreaDefs)) // event type -> index into areas
	for i, def := range controlAreaDefs {
		areas[i] = ControlArea{Code: def.code, Name: def.name, EventTypes: def.eventTypes}
		for _, et := range def.eventTypes {
			claimed[et] = i
		}
	}
	uncategorized := ControlArea{Code: uncategorizedCode, Name: uncategorizedName}
	acc := newAreaAccumulators(len(areas))
	uncatAcc := newAreaAccumulator()
	uncatTypes := map[audit.EventType]struct{}{}
	for _, e := range bundle.Events {
		if e == nil {
			continue // defensive: a hand-crafted bundle could carry a JSON null entry
		}
		if idx, ok := claimed[e.Type]; ok {
			acc[idx].add(e)
			continue
		}
		uncatAcc.add(e)
		uncatTypes[e.Type] = struct{}{}
	}
	for i := range areas {
		acc[i].apply(&areas[i])
	}
	uncatAcc.apply(&uncategorized)
	uncategorized.EventTypes = sortedEventTypes(uncatTypes)

	return &SOC2Report{
		FormatVersion:     SOC2FormatVersion,
		GeneratedAt:       time.Now().UTC(),
		MappingDisclaimer: MappingDisclaimer,
		Chain:             chainAttestation(bundle, chainVerified),
		ControlAreas:      areas,
		Uncategorized:     uncategorized,
	}, nil
}

// VerifyAndBuildSOC2Report re-verifies bundle's hash-chain segment
// BEFORE building the report — fail-closed: an unverifiable/tampered
// bundle NEVER produces a report (a broken chain segment is a returned
// error, not a report with Chain.Verified:false handed to an auditor as
// if it were usable evidence).
func VerifyAndBuildSOC2Report(bundle *auditexport.ExportBundle) (*SOC2Report, error) {
	if bundle == nil {
		return nil, auditexport.ErrNilBundle
	}
	if err := auditexport.VerifyExportBundle(bundle); err != nil {
		return nil, err
	}
	return BuildSOC2Report(bundle, true)
}

// chainAttestation projects bundle's tamper-evidence metadata into the
// report WITHOUT its Events slice.
func chainAttestation(bundle *auditexport.ExportBundle, verified bool) ChainAttestation {
	return ChainAttestation{
		Verified:          verified,
		BundleFormat:      bundle.FormatVersion,
		BundleGeneratedAt: bundle.GeneratedAt,
		Contiguous:        bundle.Contiguous,
		BoundaryPrevHash:  bundle.BoundaryPrevHash,
		HeadHash:          bundle.HeadHash,
		EventCount:        bundle.EventCount,
		Filter:            bundle.Filter,
	}
}

// sortedEventTypes returns the keys of s sorted lexically, so
// ControlArea.EventTypes is deterministic across runs (map iteration
// order is not) — required for both stable JSON output and
// reproducible tests.
func sortedEventTypes(s map[audit.EventType]struct{}) []audit.EventType {
	out := make([]audit.EventType, 0, len(s))
	for et := range s {
		out = append(out, et)
	}
	sortEventTypes(out)
	return out
}
