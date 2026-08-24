package activation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

type MemoryStoreOption func(*MemoryStore)

func WithClock(now func() time.Time) MemoryStoreOption {
	return func(store *MemoryStore) {
		if now != nil {
			store.now = now
		}
	}
}

func WithTicketTTL(ttl time.Duration) MemoryStoreOption {
	return func(store *MemoryStore) {
		if ttl > 0 {
			store.ticketTTL = ttl
		}
	}
}

type MemoryStore struct {
	mu              sync.Mutex
	now             func() time.Time
	ticketTTL       time.Duration
	codes           map[string]*memoryCode
	keyIndex        map[string]string
	invitationIndex map[string]string
	tickets         map[string]memoryTicket
	bindings        map[string]*AccountContext
}

type memoryCode struct {
	code   Code
	claims map[string]struct{}
}

type memoryTicket struct {
	codeID     string
	clientID   string
	productID  string
	tenantHint string
	expiresAt  time.Time
}

func NewMemoryStore(options ...MemoryStoreOption) *MemoryStore {
	store := &MemoryStore{
		now:             time.Now,
		ticketTTL:       DefaultTicketTTL,
		codes:           make(map[string]*memoryCode),
		keyIndex:        make(map[string]string),
		invitationIndex: make(map[string]string),
		tickets:         make(map[string]memoryTicket),
		bindings:        make(map[string]*AccountContext),
	}
	for _, option := range options {
		if option != nil {
			option(store)
		}
	}
	return store
}

// AddCode is a provisioning seam for operators and tests. The plaintext
// credential is hashed before it enters the store and is never returned.
func (s *MemoryStore) AddCode(ctx context.Context, code Code) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateCode(code); err != nil {
		return err
	}
	keyHash, invitationHash := credentialHashes(code)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.codes[code.ID]; exists || keyHash != "" && s.keyIndex[keyHash] != "" || invitationHash != "" && s.invitationIndex[invitationHash] != "" {
		return ErrCodeConflict
	}
	copyCode := cloneCode(code)
	copyCode.Key = ""
	copyCode.InvitationCode = ""
	s.codes[code.ID] = &memoryCode{code: copyCode, claims: make(map[string]struct{})}
	if keyHash != "" {
		s.keyIndex[keyHash] = code.ID
	}
	if invitationHash != "" {
		s.invitationIndex[invitationHash] = code.ID
	}
	return nil
}

func (s *MemoryStore) Prepare(ctx context.Context, input PrepareInput) (*Preparation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validatePrepareInput(input); err != nil {
		return nil, err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	code := s.lookupCode(input)
	if code == nil || !codeAvailable(code, now) || code.code.ProductID != input.ProductID ||
		(input.TenantHint != "" && input.TenantHint != code.code.TenantID) || claimsFull(code) {
		return nil, ErrInvalidActivation
	}
	rawTicket, err := randomTicket()
	if err != nil {
		return nil, err
	}
	expiresAt := now.Add(s.ticketTTL)
	s.tickets[digest(rawTicket)] = memoryTicket{
		codeID: code.code.ID, clientID: input.ClientID, productID: input.ProductID,
		tenantHint: input.TenantHint, expiresAt: expiresAt,
	}
	return &Preparation{Ticket: rawTicket, ProductID: input.ProductID, ExpiresAt: expiresAt}, nil
}

func (s *MemoryStore) Claim(ctx context.Context, input ClaimInput) (*AccountContext, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateClaimInput(input); err != nil {
		return nil, err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	ticket, ok := s.tickets[digest(input.Ticket)]
	if !ok || !now.Before(ticket.expiresAt) || ticket.clientID != input.ClientID || ticket.productID != input.ProductID {
		delete(s.tickets, digest(input.Ticket))
		return nil, ErrInvalidActivation
	}
	code, ok := s.codes[ticket.codeID]
	if !ok || !codeAvailable(code, now) || claimsFullForOther(code, input.Subject) {
		return nil, ErrInvalidActivation
	}
	bindingKey := bindingKey(input.ClientID, input.ProductID, input.Subject)
	if existing := s.bindings[bindingKey]; existing != nil {
		delete(s.tickets, digest(input.Ticket))
		return cloneContext(existing), nil
	}
	if ticket.tenantHint != "" && ticket.tenantHint != code.code.TenantID {
		return nil, ErrInvalidActivation
	}
	code.claims[input.Subject] = struct{}{}
	result := &AccountContext{ProductID: input.ProductID, TenantID: code.code.TenantID, Entitlement: cloneEntitlement(code.code.Entitlement)}
	s.bindings[bindingKey] = result
	delete(s.tickets, digest(input.Ticket))
	return cloneContext(result), nil
}

func (s *MemoryStore) Current(ctx context.Context, input CurrentInput) (*AccountContext, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateCurrentInput(input); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result := s.bindings[bindingKey(input.ClientID, input.ProductID, input.Subject)]
	if result == nil {
		return nil, ErrInvalidActivation
	}
	return cloneContext(result), nil
}

func (s *MemoryStore) lookupCode(input PrepareInput) *memoryCode {
	if input.LicenseKey != "" {
		return s.codes[s.keyIndex[digest(input.LicenseKey)]]
	}
	return s.codes[s.invitationIndex[digest(input.InvitationCode)]]
}

func validateCode(code Code) error {
	if !validIdentifier(code.ID) || !validIdentifier(code.ProductID) || !validIdentifier(code.TenantID) ||
		(code.Key == "") == (code.InvitationCode == "") || code.MaxClaims < 0 {
		return ErrInvalidCode
	}
	if code.Entitlement != nil && code.Entitlement.TenantID != code.TenantID {
		return ErrInvalidCode
	}
	return nil
}

func credentialHashes(code Code) (string, string) {
	if code.Key != "" {
		return digest(code.Key), ""
	}
	return "", digest(code.InvitationCode)
}

func codeAvailable(code *memoryCode, now time.Time) bool {
	return code != nil && (code.code.ExpiresAt.IsZero() || now.Before(code.code.ExpiresAt))
}

func claimsFull(code *memoryCode) bool {
	return len(code.claims) >= maxClaims(code.code)
}

func claimsFullForOther(code *memoryCode, subject string) bool {
	if _, exists := code.claims[subject]; exists {
		return false
	}
	return claimsFull(code)
}

func maxClaims(code Code) int {
	if code.MaxClaims <= 0 {
		return 1
	}
	return code.MaxClaims
}

func randomTicket() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// NewTicket creates the opaque short-lived value carried between setup and
// the authenticated claim. Stores persist only CredentialDigest(ticket).
func NewTicket() (string, error) { return randomTicket() }

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// CredentialDigest returns the storage lookup digest for an opaque credential.
// It is safe to persist; callers must never use it as the credential itself.
func CredentialDigest(value string) string { return digest(value) }

func bindingKey(clientID, productID, subject string) string {
	return clientID + "\x00" + productID + "\x00" + subject
}

func cloneCode(code Code) Code {
	code.Entitlement = cloneEntitlement(code.Entitlement)
	return code
}

func cloneContext(value *AccountContext) *AccountContext {
	if value == nil {
		return nil
	}
	return &AccountContext{ProductID: value.ProductID, TenantID: value.TenantID, Entitlement: cloneEntitlement(value.Entitlement)}
}

func cloneEntitlement(value *commerce.EntitlementSnapshot) *commerce.EntitlementSnapshot {
	if value == nil {
		return nil
	}
	copyValue := *value
	copyValue.Features = make(map[commerce.FeatureKey]bool, len(value.Features))
	for key, enabled := range value.Features {
		copyValue.Features[key] = enabled
	}
	copyValue.Limits = make(map[commerce.LimitKey]commerce.LimitGrant, len(value.Limits))
	for key, grant := range value.Limits {
		copyValue.Limits[key] = grant
	}
	return &copyValue
}

var _ Store = (*MemoryStore)(nil)
