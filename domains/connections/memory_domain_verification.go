package connections

import (
	"context"
	"strings"
	"time"
)

// reconcileClaimsLocked aligns connID's ownership claims with the domains the
// upserted connection declares. Domains dropped from the declaration lose their
// claim (and routing if this connection owned it). In the default (opt-out)
// mode every declared domain is claimed-and-promoted, preserving byte-identical
// last-write-wins routing; in the hardened mode a NEW claim is left pending
// (Upsert never promotes), so an unproven claim cannot steal a competing
// verified owner's routing. Caller holds m.mu.
func (m *MemoryStore) reconcileClaimsLocked(c *Connection) error {
	desired := normalizedDomainSet(c.Domains)
	m.dropUndeclaredClaimsLocked(c.ID, desired)
	for d := range desired {
		if err := m.ensureClaimLocked(c.ID, d); err != nil {
			return err
		}
		if !m.cfg.DomainVerificationRequired {
			m.promoteDomainLocked(c.ID, d)
		}
	}
	return nil
}

// dropUndeclaredClaimsLocked removes connID's claims for domains it no longer
// declares, and clears any routing entry it owned for them. Caller holds m.mu.
func (m *MemoryStore) dropUndeclaredClaimsLocked(connID string, desired map[string]struct{}) {
	for d := range m.claims[connID] {
		if _, ok := desired[d]; ok {
			continue
		}
		delete(m.claims[connID], d)
		if m.domainIndex[d] == connID {
			delete(m.domainIndex, d)
		}
	}
}

// ensureClaimLocked creates a fresh pending claim (with a new token) for
// (connID, domain) if none exists; an existing claim is left untouched so a
// re-Upsert is idempotent (token + verified status preserved). Caller holds m.mu.
func (m *MemoryStore) ensureClaimLocked(connID, domain string) error {
	if m.claims[connID] == nil {
		m.claims[connID] = make(map[string]*DomainVerification)
	}
	if _, ok := m.claims[connID][domain]; ok {
		return nil
	}
	tok, err := GenerateDomainToken()
	if err != nil {
		return err
	}
	m.claims[connID][domain] = &DomainVerification{
		ConnectionID: connID,
		Domain:       domain,
		Status:       DomainPending,
		Token:        tok,
		CreatedAt:    time.Now().UTC(),
	}
	return nil
}

// promoteDomainLocked marks connID's claim on domain verified, demotes any other
// connection currently verified on it (DNS control changing hands supersedes a
// stale claim), and installs connID as the routing owner. Caller holds m.mu.
func (m *MemoryStore) promoteDomainLocked(connID, domain string) {
	claim := m.claims[connID][domain]
	if claim == nil {
		return
	}
	for otherID, byDomain := range m.claims {
		if otherID == connID {
			continue
		}
		if oc, ok := byDomain[domain]; ok && oc.Status == DomainVerified {
			oc.Status = DomainPending
			oc.VerifiedAt = time.Time{}
		}
	}
	claim.Status = DomainVerified
	claim.VerifiedAt = time.Now().UTC()
	m.domainIndex[domain] = connID
}

func (m *MemoryStore) DomainClaim(_ context.Context, connID, domain string) (*DomainVerification, error) {
	d := strings.ToLower(strings.TrimSpace(domain))
	m.mu.RLock()
	defer m.mu.RUnlock()
	claim, ok := m.claims[connID][d]
	if !ok {
		return nil, ErrNoDomainClaim
	}
	return m.cloneClaimLocked(claim), nil
}

func (m *MemoryStore) DomainClaims(_ context.Context, connID string) ([]*DomainVerification, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	byDomain := m.claims[connID]
	out := make([]*DomainVerification, 0, len(byDomain))
	for _, c := range byDomain {
		out = append(out, m.cloneClaimLocked(c))
	}
	return out, nil
}

func (m *MemoryStore) VerifyDomain(_ context.Context, connID, domain string) error {
	d := strings.ToLower(strings.TrimSpace(domain))
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.claims[connID][d]; !ok {
		return ErrNoDomainClaim
	}
	m.promoteDomainLocked(connID, d)
	return nil
}

// VerifyDomainWithToken atomically checks the current claim token and promotes
// it while holding the store lock. A DNS proof for a replaced claim therefore
// cannot promote the replacement.
func (m *MemoryStore) VerifyDomainWithToken(_ context.Context, connID, domain, token string) (bool, error) {
	d := strings.ToLower(strings.TrimSpace(domain))
	m.mu.Lock()
	defer m.mu.Unlock()
	claim, ok := m.claims[connID][d]
	if !ok {
		return false, ErrNoDomainClaim
	}
	if claim.Token != token {
		return false, nil
	}
	m.promoteDomainLocked(connID, d)
	return true, nil
}

// cloneClaimLocked copies a claim and derives its public Record name from the
// store's configured prefix, so callers never mutate stored state and never need
// to know the prefix. Caller holds m.mu.
func (m *MemoryStore) cloneClaimLocked(c *DomainVerification) *DomainVerification {
	cp := *c
	cp.Record = DomainVerificationRecordName(m.cfg.RecordPrefix, c.Domain)
	return &cp
}

// normalizedDomainSet lowercases + trims the declared domains, dropping empties.
func normalizedDomainSet(domains []string) map[string]struct{} {
	set := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		if nd := strings.ToLower(strings.TrimSpace(d)); nd != "" {
			set[nd] = struct{}{}
		}
	}
	return set
}
