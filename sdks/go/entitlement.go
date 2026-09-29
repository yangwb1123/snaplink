package snaplink

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The server is always the authority on what a tenant may do. This file exists
// so a caller never has to know the wire shape of an entitlement in order to
// decide whether a feature is available, and so a lapsed entitlement is never
// mistaken for a live one.
//
// Entitlement.StateAt reproduces commerce.EntitlementSnapshot.effective
// exactly: an entitlement is effective only when Active is set, now is not
// before EffectiveAt, and ExpiresAt is zero or strictly after now. A presence
// check cannot make that distinction, which is why LicenseState has three kinds
// rather than a bare pointer.

// Feature is a stable product capability identifier, mirroring
// commerce.FeatureKey.
type Feature string

// The feature keys the server currently defines, in declaration order.
const (
	FeatureCoreSSO          Feature = "core_sso"
	FeatureMultiTenant      Feature = "multi_tenant"
	FeatureAuditGovernance  Feature = "audit_governance"
	FeatureNotifications    Feature = "notifications"
	FeatureIM               Feature = "im"
	FeatureAccount          Feature = "account"
	FeatureVault            Feature = "vault"
	FeatureSCIM             Feature = "scim"
	FeatureFederation       Feature = "federation"
	FeatureHighAvailability Feature = "high_availability"
)

// AllFeatures returns every feature key this build knows.
func AllFeatures() []Feature {
	return []Feature{
		FeatureCoreSSO, FeatureMultiTenant, FeatureAuditGovernance,
		FeatureNotifications, FeatureIM, FeatureAccount, FeatureVault,
		FeatureSCIM, FeatureFederation, FeatureHighAvailability,
	}
}

// knownFeature reports whether the key is one this build defines.
//
// Feature is a string type, so Feature("anything") is constructible. A typed
// constant alone would not stop a caller from handing Has an arbitrary key and
// having it granted; the lookup must reject it, the way the enum-backed
// implementations reject it for free.
func knownFeature(feature Feature) bool {
	for _, known := range AllFeatures() {
		if known == feature {
			return true
		}
	}
	return false
}

// Limit is a stable quota dimension, mirroring commerce.LimitKey.
type Limit string

// The limit keys the server currently defines, in declaration order.
const (
	LimitUsers          Limit = "users"
	LimitClients        Limit = "clients"
	LimitSessions       Limit = "sessions"
	LimitTokenRate      Limit = "token_rate"
	LimitStorageBytes   Limit = "storage_bytes"
	LimitStorageObjects Limit = "storage_objects"
)

// AllLimits returns every limit key this build knows.
func AllLimits() []Limit {
	return []Limit{
		LimitUsers, LimitClients, LimitSessions,
		LimitTokenRate, LimitStorageBytes, LimitStorageObjects,
	}
}

// knownLimit reports whether the key is one this build defines; see
// knownFeature for why the check cannot be left to the type.
func knownLimit(limit Limit) bool {
	for _, known := range AllLimits() {
		if known == limit {
			return true
		}
	}
	return false
}

// InactiveReason explains why an entitlement is present but not usable.
//
// Presentation only. It must never drive retry or authorization behaviour: the
// server collapses distinct internal causes into one wire code, and a client
// that branched on the reason would leak the distinction the server hides.
type InactiveReason string

// The inactive reasons this build reports.
const (
	InactiveNotYetEffective InactiveReason = "not_yet_effective"
	InactiveExpired         InactiveReason = "expired"
	InactiveSuspended       InactiveReason = "suspended"
)

// LicenseStateKind names which of the three states a licence is in.
type LicenseStateKind string

// The three states a product licence can be in.
//
// A two-state pointer cannot tell "never activated" from "activated once but
// lapsed", and those need different copy and different follow-up actions.
const (
	StateNotActivated LicenseStateKind = "not_activated"
	StateInactive     LicenseStateKind = "inactive"
	StateActive       LicenseStateKind = "active"
)

// LicenseState is the classified state of a product licence.
type LicenseState struct {
	Kind        LicenseStateKind
	Reason      InactiveReason
	Until       time.Time
	Entitlement *Entitlement
}

// Active reports whether grants are live. This is the only question a feature
// gate should ask.
func (s LicenseState) Active() bool { return s.Kind == StateActive }

// LimitGrant is a soft threshold and a hard safety limit.
//
// Unlimited short-circuits the pair: an unlimited grant reports zero for both
// thresholds, so a caller reading Soft alone would see a bogus number. Always
// check Unlimited.
type LimitGrant struct {
	Soft      int64 `json:"soft"`
	Hard      int64 `json:"hard"`
	Unlimited bool  `json:"unlimited,omitempty"`
}

// PlanRef is a plan identifier and its immutable published version.
type PlanRef struct {
	ID      string `json:"id"`
	Version uint64 `json:"version"`
}

// Entitlement is a server-derived commercial entitlement snapshot.
//
// Feature and limit maps are keyed by their wire keys so a key this build
// predates is preserved rather than dropped, while lookups stay type-safe.
type Entitlement struct {
	TenantID       string                `json:"tenant_id"`
	SubscriptionID string                `json:"subscription_id"`
	Plan           PlanRef               `json:"plan"`
	Revision       uint64                `json:"revision"`
	Active         bool                  `json:"active"`
	Features       map[string]bool       `json:"features"`
	Limits         map[string]LimitGrant `json:"limits"`
	EffectiveAt    time.Time             `json:"effective_at"`
	ExpiresAt      time.Time             `json:"expires_at,omitempty"`
	GeneratedAt    time.Time             `json:"generated_at"`
}

// NewEntitlement decodes an entitlement from the wire. A missing or malformed
// timestamp is treated as absent rather than guessed.
//
// The wire form is decoded in full rather than field by field: time.Time's own
// UnmarshalJSON rejects a bare integer, and the fixtures and hand-written
// entitlement files use Unix seconds, so every timestamp must go through
// flexTime.
func NewEntitlement(raw json.RawMessage) (*Entitlement, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var wire struct {
		TenantID       string                `json:"tenant_id"`
		SubscriptionID string                `json:"subscription_id"`
		Plan           PlanRef               `json:"plan"`
		Revision       uint64                `json:"revision"`
		Active         bool                  `json:"active"`
		Features       map[string]bool       `json:"features"`
		Limits         map[string]LimitGrant `json:"limits"`
		EffectiveAt    flexTime              `json:"effective_at"`
		ExpiresAt      flexTime              `json:"expires_at"`
		GeneratedAt    flexTime              `json:"generated_at"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("snaplink: malformed entitlement: %w", err)
	}
	return &Entitlement{
		TenantID:       wire.TenantID,
		SubscriptionID: wire.SubscriptionID,
		Plan:           wire.Plan,
		Revision:       wire.Revision,
		Active:         wire.Active,
		Features:       wire.Features,
		Limits:         wire.Limits,
		EffectiveAt:    wire.EffectiveAt.Time,
		ExpiresAt:      wire.ExpiresAt.Time,
		GeneratedAt:    wire.GeneratedAt.Time,
	}, nil
}

// StateAt classifies the entitlement at now.
//
// Mirrors commerce.EntitlementSnapshot.effective exactly: the ExpiresAt
// boundary is exclusive, so an entitlement whose window closes at t is already
// inactive at t.
func (e *Entitlement) StateAt(now time.Time) LicenseState {
	if e == nil {
		return LicenseState{Kind: StateNotActivated}
	}
	if !e.Active {
		return LicenseState{Kind: StateInactive, Reason: InactiveSuspended, Until: e.ExpiresAt}
	}
	if now.Before(e.EffectiveAt) {
		return LicenseState{Kind: StateInactive, Reason: InactiveNotYetEffective}
	}
	if !e.ExpiresAt.IsZero() && !now.Before(e.ExpiresAt) {
		return LicenseState{Kind: StateInactive, Reason: InactiveExpired, Until: e.ExpiresAt}
	}
	return LicenseState{Kind: StateActive, Entitlement: e}
}

// Has reports whether feature is granted at now.
//
// Returns false for an inactive entitlement regardless of what the map says,
// and false for a key this build does not recognise.
func (e *Entitlement) Has(feature Feature, now time.Time) bool {
	if !e.StateAt(now).Active() {
		return false
	}
	if !knownFeature(feature) {
		return false
	}
	return e.Features[string(feature)]
}

// Limit returns the grant for limit at now, reporting false when inactive,
// absent, or not a key this build recognises.
func (e *Entitlement) Limit(limit Limit, now time.Time) (LimitGrant, bool) {
	if !e.StateAt(now).Active() || !knownLimit(limit) {
		return LimitGrant{}, false
	}
	grant, ok := e.Limits[string(limit)]
	return grant, ok
}

// UnknownFeatures returns feature keys the server sent that this build does not
// recognise, so an operator can see a plan grants something the SDK cannot yet
// gate instead of silently ignoring it.
func (e *Entitlement) UnknownFeatures() []string {
	if e == nil {
		return nil
	}
	var unknown []string
	for key := range e.Features {
		if !knownFeature(Feature(key)) {
			unknown = append(unknown, key)
		}
	}
	return unknown
}

// License classifies the licence at now.
//
// The raw AccountContext.Entitlement map is kept as the wire view; this is the
// typed one. A nil map means the product was never activated, which is a
// different state from an entitlement that exists and has lapsed.
func (c AccountContext) License(now time.Time) LicenseState {
	entitlement, err := c.TypedEntitlement()
	if err != nil || entitlement == nil {
		return LicenseState{Kind: StateNotActivated}
	}
	return entitlement.StateAt(now)
}

// TypedEntitlement returns the entitlement as a typed value, or nil when the
// product was never activated.
func (c AccountContext) TypedEntitlement() (*Entitlement, error) {
	if c.Entitlement == nil {
		return nil, nil
	}
	raw, err := json.Marshal(c.Entitlement)
	if err != nil {
		return nil, fmt.Errorf("snaplink: malformed entitlement: %w", err)
	}
	return NewEntitlement(raw)
}

// HasFeature reports whether feature is granted at now. It is false when the
// product was never activated and false when the entitlement has lapsed.
func (c AccountContext) HasFeature(feature Feature, now time.Time) bool {
	entitlement, err := c.TypedEntitlement()
	if err != nil {
		return false
	}
	return entitlement.Has(feature, now)
}

// flexTime accepts the RFC 3339 form Go's time.Time serialises, a Unix-seconds
// integer as a fixture or hand-written file may use, and null.
type flexTime struct {
	Time time.Time
}

func (f *flexTime) UnmarshalJSON(data []byte) error {
	text := strings.TrimSpace(strings.Trim(strings.TrimSpace(string(data)), `"`))
	if text == "" || text == "null" {
		f.Time = time.Time{}
		return nil
	}
	if seconds, err := strconv.ParseInt(text, 10, 64); err == nil {
		f.Time = time.Unix(seconds, 0).UTC()
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, text)
	if err != nil {
		return fmt.Errorf("snaplink: %q is not an RFC 3339 timestamp or Unix seconds", text)
	}
	f.Time = parsed.UTC()
	return nil
}
