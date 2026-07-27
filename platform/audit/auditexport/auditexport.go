// Package auditexport builds and verifies self-contained, tamper-evident
// bulk exports of the audit hash chain for compliance evidence.
//
// An [ExportBundle] carries a filtered, chain-ordered slice of audit
// events plus a boundary anchor (the PrevHash the oldest exported event
// held at export time) and the head Hash. The anchor is what lets a
// date-range export that does NOT start at true chain genesis stay
// independently verifiable via [VerifyExportBundle]: the persisted
// Hash/PrevHash values are copied VERBATIM and never recomputed, so a
// bundle a SOC2 auditor spot-checks against the live database shows
// identical hashes.
//
// Read-only: it pages the store through [QueryPager] (every audit.Sink
// satisfies it structurally) and NEVER writes, re-hashes, or mutates the
// live chain. The "prune + re-chain the surviving live events" migration
// the SQLite sink's maintenance doc describes is a separate, mutating
// operation deliberately out of scope here.
//
// Contiguity: a pure time-window (or full) export selects a CONTIGUOUS
// run of the chain, so its linkage verifies via the boundary anchor. An
// attribute filter (type/actor/tenant/…) selects a NON-contiguous subset
// that skips intervening events; such a bundle is marked !Contiguous and
// verifies per-event integrity only (each event's content is still
// tamper-evident; completeness is not chain-provable). [VerifyExportBundle]
// applies the matching check automatically.
//
// Limitation: pagination is OFFSET-based (mirroring the audit query API
// and the audit-verify CLI), which degrades on very large offsets over
// very large tables; keyset/cursor pagination is a future upgrade.
package auditexport

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
)

// FormatVersion is the ExportBundle schema version stamped into every
// bundle and required by [VerifyExportBundle]. Bump only on a breaking
// layout change so an old reader rejects a newer evidence file loudly
// instead of verifying against a mismatched schema.
const FormatVersion = 1

// exportPageSize bounds the per-page memory of the paging loop; it
// matches the audit query API's hard cap so one page never asks the
// store for more than it will return.
const exportPageSize = audit.MaxQueryLimit

// Sentinels — SDK Go errors, not HTTP wire codes; they never appear in
// any response this server emits.
var (
	// ErrNilPager is returned by BuildExportBundle when pager is nil.
	ErrNilPager = errors.New("auditexport: nil pager")
	// ErrNilBundle is returned by VerifyExportBundle when the bundle is nil.
	ErrNilBundle = errors.New("auditexport: nil bundle")
	// ErrUnsupportedFormat is returned by VerifyExportBundle when the
	// bundle's FormatVersion is not FormatVersion.
	ErrUnsupportedFormat = errors.New("auditexport: unsupported bundle format version")
)

// QueryPager is the read-only slice of an audit.Sink that
// BuildExportBundle needs: page through events matching a Query. Every
// audit sink (MemorySink, sqlite.Sink) satisfies it structurally, and a
// remote HTTP-backed adapter can implement just this one method.
type QueryPager interface {
	Query(ctx context.Context, q audit.Query) ([]*audit.Event, error)
}

// ExportFilter is the snake_case projection of the audit.Query used for
// an export, echoed into the bundle so the evidence file is
// self-describing. The shared audit.Query type carries no json tags; a
// dedicated struct keeps the wire format consistently snake_case without
// tagging the shared type. Field names mirror the audit query-string
// parameters (see platform/audit/handlers.go).
type ExportFilter struct {
	Type      string     `json:"type,omitempty"`
	Outcome   string     `json:"outcome,omitempty"`
	ActorID   string     `json:"actor_id,omitempty"`
	ClientID  string     `json:"client_id,omitempty"`
	TenantID  string     `json:"tenant_id,omitempty"`
	Provider  string     `json:"provider,omitempty"`
	RequestID string     `json:"request_id,omitempty"`
	TraceID   string     `json:"trace_id,omitempty"`
	Since     *time.Time `json:"since,omitempty"`
	Until     *time.Time `json:"until,omitempty"`
}

// ExportBundle is the self-contained evidence envelope for a bulk audit
// extract. Events are in CHAIN ORDER (oldest first) with their ORIGINAL
// persisted Hash/PrevHash — never recomputed.
type ExportBundle struct {
	FormatVersion int          `json:"format_version"`
	GeneratedAt   time.Time    `json:"generated_at"`
	Filter        ExportFilter `json:"filter"`
	// Contiguous is true when the export is a whole time-range/full
	// segment (chain-continuity verifiable via BoundaryPrevHash); false
	// for an attribute-filtered subset (only per-event integrity holds).
	Contiguous bool `json:"contiguous"`
	// BoundaryPrevHash is the PrevHash of the first exported event —
	// GenesisHash iff the export starts at true chain genesis.
	BoundaryPrevHash string `json:"boundary_prev_hash"`
	// HeadHash is the Hash of the last exported event, an external anchor
	// for the head (whose tampering the chain alone cannot detect).
	HeadHash   string         `json:"head_hash,omitempty"`
	EventCount int            `json:"event_count"`
	Events     []*audit.Event `json:"events"`
}

// BuildExportBundle pages pager for every event matching q — honoring
// q's filter fields, q.Since/q.Until, q.Offset as a starting offset, and
// q.Limit (>0) as a total cap — assembles a chain-ordered ExportBundle,
// and self-verifies it before returning (fail-closed: a broken segment
// or tampered event is a returned error, never a silently-invalid
// bundle).
func BuildExportBundle(ctx context.Context, pager QueryPager, q audit.Query) (*ExportBundle, error) {
	if pager == nil {
		return nil, ErrNilPager
	}
	events, err := pageAll(ctx, pager, q)
	if err != nil {
		return nil, err
	}
	b := &ExportBundle{
		FormatVersion:    FormatVersion,
		GeneratedAt:      time.Now().UTC(),
		Filter:           filterFromQuery(q),
		Contiguous:       isContiguousQuery(q),
		BoundaryPrevHash: boundaryPrevHash(events),
		HeadHash:         headHash(events),
		EventCount:       len(events),
		Events:           events,
	}
	if err := VerifyExportBundle(b); err != nil {
		return nil, fmt.Errorf("auditexport: built bundle failed self-verify: %w", err)
	}
	return b, nil
}

// VerifyExportBundle re-verifies a previously built or file-loaded
// bundle: a supported format version, a head Hash consistent with the
// events, and — per Contiguous — either full chain-segment continuity
// (anchored at BoundaryPrevHash) or per-event integrity. Reuses the
// audit package's verifiers so a bundle and the live chain agree by
// construction.
func VerifyExportBundle(b *ExportBundle) error {
	if b == nil {
		return ErrNilBundle
	}
	if b.FormatVersion != FormatVersion {
		return fmt.Errorf("%w: got %d, want %d", ErrUnsupportedFormat, b.FormatVersion, FormatVersion)
	}
	if b.HeadHash != headHash(b.Events) {
		return fmt.Errorf("auditexport: head_hash %q does not match last event", b.HeadHash)
	}
	if b.Contiguous {
		return audit.VerifyChainSegment(b.Events, b.BoundaryPrevHash)
	}
	return audit.VerifyEventIntegrity(b.Events)
}

// pageAll pages pager newest-first (the sink ordering) until a short
// page or q.Limit is reached, then reverses into oldest-first chain
// order. OFFSET-based, matching the audit query API; a static export
// window makes the offsets consistent.
func pageAll(ctx context.Context, pager QueryPager, q audit.Query) ([]*audit.Event, error) {
	total := q.Limit // 0 = unbounded
	pageQ := q
	pageQ.Limit = exportPageSize
	offset := q.Offset
	var collected []*audit.Event
	for {
		pageQ.Offset = offset
		page, err := pager.Query(ctx, pageQ)
		if err != nil {
			return nil, fmt.Errorf("auditexport: query (offset=%d): %w", offset, err)
		}
		collected = append(collected, page...)
		if total > 0 && len(collected) >= total {
			collected = collected[:total]
			break
		}
		if len(page) < exportPageSize {
			break
		}
		offset += len(page)
	}
	reverse(collected)
	return collected, nil
}

// isContiguousQuery reports whether q selects a CONTIGUOUS run of the
// chain — true for a pure time-window / full export, false once any
// attribute equality filter is set. Time bounds, Limit, and Offset
// preserve contiguity; attribute filters skip intervening events.
func isContiguousQuery(q audit.Query) bool {
	return q.Type == "" && q.Outcome == "" && q.ActorID == "" &&
		q.ClientID == "" && q.TenantID == "" && q.Provider == "" &&
		q.RequestID == "" && q.TraceID == ""
}

// boundaryPrevHash is the anchor for VerifyChainSegment: the PrevHash the
// oldest exported event carried. GenesisHash for an empty export.
func boundaryPrevHash(events []*audit.Event) string {
	if len(events) == 0 {
		return audit.GenesisHash
	}
	return events[0].PrevHash
}

// headHash is the Hash of the last exported event, or "" when empty.
func headHash(events []*audit.Event) string {
	if len(events) == 0 {
		return ""
	}
	return events[len(events)-1].Hash
}

func filterFromQuery(q audit.Query) ExportFilter {
	f := ExportFilter{
		Type:      string(q.Type),
		Outcome:   string(q.Outcome),
		ActorID:   q.ActorID,
		ClientID:  q.ClientID,
		TenantID:  q.TenantID,
		Provider:  q.Provider,
		RequestID: q.RequestID,
		TraceID:   q.TraceID,
	}
	if !q.Since.IsZero() {
		s := q.Since.UTC()
		f.Since = &s
	}
	if !q.Until.IsZero() {
		u := q.Until.UTC()
		f.Until = &u
	}
	return f
}

func reverse(s []*audit.Event) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
