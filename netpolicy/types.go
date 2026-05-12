package netpolicy

import (
	"errors"
	"maps"
	"time"
)

// Policy is one declarative class of network. The zero value is invalid:
// at least one of CIDRs or Hostnames must be non-empty for a policy to be
// addressable by Classify.
type Policy struct {
	Name      string            `json:"name"`
	CIDRs     []string          `json:"cidrs,omitempty"`
	Hostnames []string          `json:"hostnames,omitempty"`
	Priority  int32             `json:"priority,omitempty"`

	AdvertisedBaseURL   string `json:"advertised_base_url,omitempty"`
	AdvertisedJWKSURL   string `json:"advertised_jwks_url,omitempty"`
	AdvertisedLogoutURL string `json:"advertised_logout_url,omitempty"`

	Metadata map[string]string `json:"metadata,omitempty"`

	// Set by the Store on every Apply. Read-only outside the store.
	Version   int64     `json:"version,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
}

// Clone returns a deep-enough copy that mutating the result is safe (slices
// and maps are duplicated). Used by the Classifier when handing snapshots
// out so callers can't poison the internal index.
func (p *Policy) Clone() *Policy {
	if p == nil {
		return nil
	}
	cp := *p
	if p.CIDRs != nil {
		cp.CIDRs = append([]string(nil), p.CIDRs...)
	}
	if p.Hostnames != nil {
		cp.Hostnames = append([]string(nil), p.Hostnames...)
	}
	if p.Metadata != nil {
		cp.Metadata = make(map[string]string, len(p.Metadata))
		maps.Copy(cp.Metadata, p.Metadata)
	}
	return &cp
}

// EventType discriminates a Watch event.
type EventType string

const (
	EventAdded   EventType = "added"
	EventUpdated EventType = "updated"
	EventRemoved EventType = "removed"
)

// Event is one change observed via Watch. For EventRemoved, Policy.Name is
// populated but the rest of the fields may be zero (depends on backend).
type Event struct {
	Type   EventType
	Policy *Policy
}

// ErrNotFound is returned by Get/Delete when the named policy does not exist.
var ErrNotFound = errors.New("netpolicy: not found")
