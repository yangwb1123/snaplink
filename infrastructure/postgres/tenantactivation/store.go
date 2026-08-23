// Package tenantactivation provides the shared PostgreSQL/CockroachDB adapter
// for hosted-login activation codes, tickets, and subject bindings.
package tenantactivation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/yangwb1123/snaplink/domains/tenant/activation"
	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/platform/migrate"
)

const transactionRetries = 5

type Option func(*Store)

func WithClock(now func() time.Time) Option {
	return func(store *Store) {
		if now != nil {
			store.now = now
		}
	}
}

func WithTicketTTL(ttl time.Duration) Option {
	return func(store *Store) {
		if ttl > 0 {
			store.ticketTTL = ttl
		}
	}
}

type Store struct {
	db        *sql.DB
	now       func() time.Time
	ticketTTL time.Duration
}

func NewWithDB(db *sql.DB, dialect postgresbackend.Dialect, options ...Option) (*Store, error) {
	if db == nil {
		return nil, errors.New("tenantactivation/postgres: database is required")
	}
	if err := postgresbackend.Run(context.Background(), db, "tenant_activation", migrations, dialect); err != nil {
		return nil, fmt.Errorf("tenantactivation/postgres: migrate: %w", err)
	}
	store := &Store{db: db, now: time.Now, ticketTTL: activation.DefaultTicketTTL}
	for _, option := range options {
		if option != nil {
			option(store)
		}
	}
	return store, nil
}

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("tenantactivation/postgres: store closed")
	}
	return s.db.PingContext(ctx)
}

func MaxVersion() int { return migrate.MaxVersion(migrations) }

func (s *Store) AddCode(ctx context.Context, code activation.Code) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := activation.ValidateCode(code); err != nil {
		return err
	}
	keyDigest, invitationDigest := credentialDigests(code)
	entitlement, err := marshalEntitlement(code.Entitlement)
	if err != nil {
		return err
	}
	maxClaims := code.MaxClaims
	if maxClaims <= 0 {
		maxClaims = 1
	}
	result, err := s.db.ExecContext(ctx, `
        INSERT INTO tenant_activation_codes (
            id, product_id, tenant_id, key_digest, invitation_digest,
            entitlement, expires_at_ns, max_claims, created_at_ns
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT DO NOTHING`, code.ID, code.ProductID, code.TenantID,
		keyDigest, invitationDigest, entitlement, timeNano(code.ExpiresAt), maxClaims,
		s.now().UnixNano())
	if err != nil {
		return fmt.Errorf("tenantactivation/postgres: add code: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("tenantactivation/postgres: add code result: %w", err)
	}
	if rows == 0 {
		return activation.ErrCodeConflict
	}
	return nil
}

func (s *Store) Prepare(ctx context.Context, input activation.PrepareInput) (*activation.Preparation, error) {
	if err := activation.ValidatePrepareInput(input); err != nil {
		return nil, err
	}
	now := s.now()
	digests := prepareDigests(input)
	code, err := s.findCode(ctx, digests[0], digests[1])
	if errors.Is(err, sql.ErrNoRows) {
		return nil, activation.ErrInvalidActivation
	}
	if err != nil {
		return nil, fmt.Errorf("tenantactivation/postgres: find code: %w", err)
	}
	if !code.available(now) || code.productID != input.ProductID ||
		(input.TenantHint != "" && input.TenantHint != code.tenantID) {
		return nil, activation.ErrInvalidActivation
	}
	full, err := s.codeClaimsFull(ctx, code.id, code.maxClaims)
	if err != nil {
		return nil, fmt.Errorf("tenantactivation/postgres: count claims: %w", err)
	}
	if full {
		return nil, activation.ErrInvalidActivation
	}
	ticket, err := activation.NewTicket()
	if err != nil {
		return nil, fmt.Errorf("tenantactivation/postgres: create ticket: %w", err)
	}
	expiresAt := now.Add(s.ticketTTL)
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM tenant_activation_tickets WHERE expires_at_ns <= $1`, now.UnixNano()); err != nil {
		return nil, fmt.Errorf("tenantactivation/postgres: reap tickets: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
	        INSERT INTO tenant_activation_tickets (
	            ticket_digest, code_id, client_id, product_id, tenant_hint,
	            expires_at_ns, created_at_ns
	        ) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		activation.CredentialDigest(ticket), code.id, input.ClientID, input.ProductID,
		input.TenantHint, expiresAt.UnixNano(), now.UnixNano())
	if err != nil {
		return nil, fmt.Errorf("tenantactivation/postgres: store ticket: %w", err)
	}
	return &activation.Preparation{Ticket: ticket, ProductID: input.ProductID, ExpiresAt: expiresAt}, nil
}

func (s *Store) Claim(ctx context.Context, input activation.ClaimInput) (*activation.AccountContext, error) {
	if err := activation.ValidateClaimInput(input); err != nil {
		return nil, err
	}
	var result *activation.AccountContext
	err := runTransaction(ctx, s.db, func(tx *sql.Tx) error {
		result = nil
		ticket, err := s.findTicket(tx, activation.CredentialDigest(input.Ticket))
		if err != nil {
			return s.consumeInvalid(tx, input.Ticket, err)
		}
		if !ticket.available(s.now()) || ticket.clientID != input.ClientID || ticket.productID != input.ProductID {
			return s.consumeInvalid(tx, input.Ticket, activation.ErrInvalidActivation)
		}
		code, err := s.findCodeForUpdate(tx, ticket.codeID)
		if err != nil {
			return s.consumeInvalid(tx, input.Ticket, err)
		}
		if !code.available(s.now()) || code.productID != input.ProductID ||
			(ticket.tenantHint != "" && ticket.tenantHint != code.tenantID) {
			return s.consumeInvalid(tx, input.Ticket, activation.ErrInvalidActivation)
		}
		result, err = s.findBinding(tx, input)
		if err == nil {
			return s.deleteTicket(tx, input.Ticket)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err := s.claimLimitReached(tx, code, input.Subject); err != nil {
			return s.consumeInvalid(tx, input.Ticket, err)
		}
		result, err = s.insertBinding(tx, input, code)
		if err != nil {
			return err
		}
		return s.deleteTicket(tx, input.Ticket)
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) Current(ctx context.Context, input activation.CurrentInput) (*activation.AccountContext, error) {
	if err := activation.ValidateCurrentInput(input); err != nil {
		return nil, err
	}
	var tenantID string
	var entitlement []byte
	err := s.db.QueryRowContext(ctx, `
        SELECT tenant_id, COALESCE(entitlement, 'null'::jsonb)
        FROM tenant_activation_claims
        WHERE client_id = $1 AND product_id = $2 AND subject = $3`,
		input.ClientID, input.ProductID, input.Subject).Scan(&tenantID, &entitlement)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, activation.ErrInvalidActivation
	}
	if err != nil {
		return nil, fmt.Errorf("tenantactivation/postgres: current binding: %w", err)
	}
	value, err := unmarshalEntitlement(entitlement)
	if err != nil {
		return nil, err
	}
	return &activation.AccountContext{ProductID: input.ProductID, TenantID: tenantID, Entitlement: value}, nil
}

type rowScanner interface{ Scan(...any) error }

type codeRecord struct {
	id, productID, tenantID string
	entitlement             *commerce.EntitlementSnapshot
	expiresAt               time.Time
	maxClaims               int
}

type ticketRecord struct {
	codeID, clientID, productID, tenantHint string
	expiresAt                               time.Time
}

func (s *Store) findCode(ctx context.Context, keyDigest, invitationDigest string) (codeRecord, error) {
	return readCode(s.db.QueryRowContext(ctx, `
        SELECT id, product_id, tenant_id, COALESCE(entitlement, 'null'::jsonb),
               expires_at_ns, max_claims
        FROM tenant_activation_codes
        WHERE (key_digest = $1 AND key_digest <> '')
           OR (invitation_digest = $2 AND invitation_digest <> '')`, keyDigest, invitationDigest))
}

func (s *Store) findCodeForUpdate(tx *sql.Tx, codeID string) (codeRecord, error) {
	return readCode(tx.QueryRow(`
        SELECT id, product_id, tenant_id, COALESCE(entitlement, 'null'::jsonb),
               expires_at_ns, max_claims
        FROM tenant_activation_codes WHERE id = $1 FOR UPDATE`, codeID))
}

func (s *Store) codeClaimsFull(ctx context.Context, codeID string, maxClaims int) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
        SELECT COUNT(DISTINCT subject) FROM tenant_activation_claims WHERE code_id = $1`, codeID).Scan(&count)
	return count >= maxClaims, err
}

func (s *Store) findTicket(tx *sql.Tx, digest string) (ticketRecord, error) {
	return readTicket(tx.QueryRow(`
        SELECT code_id, client_id, product_id, tenant_hint, expires_at_ns
        FROM tenant_activation_tickets WHERE ticket_digest = $1 FOR UPDATE`, digest))
}

func (s *Store) findBinding(tx *sql.Tx, input activation.ClaimInput) (*activation.AccountContext, error) {
	var tenantID string
	var entitlement []byte
	err := tx.QueryRow(`
        SELECT tenant_id, COALESCE(entitlement, 'null'::jsonb)
        FROM tenant_activation_claims
        WHERE client_id = $1 AND product_id = $2 AND subject = $3`,
		input.ClientID, input.ProductID, input.Subject).Scan(&tenantID, &entitlement)
	if err != nil {
		return nil, err
	}
	value, err := unmarshalEntitlement(entitlement)
	if err != nil {
		return nil, err
	}
	return &activation.AccountContext{ProductID: input.ProductID, TenantID: tenantID, Entitlement: value}, nil
}

func (s *Store) claimLimitReached(tx *sql.Tx, code codeRecord, subject string) error {
	var alreadyClaimed bool
	if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM tenant_activation_claims WHERE code_id = $1 AND subject = $2)`, code.id, subject).Scan(&alreadyClaimed); err != nil {
		return err
	}
	if alreadyClaimed {
		return nil
	}
	var count int
	if err := tx.QueryRow(`SELECT COUNT(DISTINCT subject) FROM tenant_activation_claims WHERE code_id = $1`, code.id).Scan(&count); err != nil {
		return err
	}
	if count >= code.maxClaims {
		return activation.ErrInvalidActivation
	}
	return nil
}

func (s *Store) insertBinding(tx *sql.Tx, input activation.ClaimInput, code codeRecord) (*activation.AccountContext, error) {
	entitlement, err := marshalEntitlement(code.entitlement)
	if err != nil {
		return nil, err
	}
	result, err := tx.Exec(`
        INSERT INTO tenant_activation_claims (
            client_id, product_id, subject, code_id, tenant_id, entitlement, claimed_at_ns
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (client_id, product_id, subject) DO NOTHING`,
		input.ClientID, input.ProductID, input.Subject, code.id, code.tenantID,
		entitlement, s.now().UnixNano())
	if err != nil {
		return nil, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if rows == 0 {
		return s.findBinding(tx, input)
	}
	return newContext(code), nil
}

func (s *Store) deleteTicket(tx *sql.Tx, rawTicket string) error {
	_, err := tx.Exec(`DELETE FROM tenant_activation_tickets WHERE ticket_digest = $1`, activation.CredentialDigest(rawTicket))
	return err
}

func (s *Store) consumeInvalid(tx *sql.Tx, rawTicket string, err error) error {
	if deleteErr := s.deleteTicket(tx, rawTicket); deleteErr != nil {
		return deleteErr
	}
	if errors.Is(err, sql.ErrNoRows) {
		err = activation.ErrInvalidActivation
	}
	return setOperationError(err)
}

type operationError struct{ err error }

func (e operationError) Error() string { return e.err.Error() }
func (e operationError) Unwrap() error { return e.err }

func setOperationError(err error) error { return operationError{err: err} }

func runTransaction(ctx context.Context, db *sql.DB, operation func(*sql.Tx) error) error {
	var err error
	for attempt := 0; attempt < transactionRetries; attempt++ {
		err = runTransactionOnce(ctx, db, operation)
		if err == nil || !serializationFailure(err) {
			return err
		}
	}
	return err
}

func runTransactionOnce(ctx context.Context, db *sql.DB, operation func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := operation(tx); err != nil {
		if operationFailure, ok := err.(operationError); ok {
			if commitErr := tx.Commit(); commitErr != nil {
				return commitErr
			}
			return operationFailure.err
		}
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func serializationFailure(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40001"
}

func credentialDigests(code activation.Code) (string, string) {
	if code.Key != "" {
		return activation.CredentialDigest(code.Key), ""
	}
	return "", activation.CredentialDigest(code.InvitationCode)
}

func prepareDigests(input activation.PrepareInput) [2]string {
	if input.LicenseKey != "" {
		return [2]string{activation.CredentialDigest(input.LicenseKey), ""}
	}
	return [2]string{"", activation.CredentialDigest(input.InvitationCode)}
}

func readCode(scanner rowScanner) (codeRecord, error) {
	var result codeRecord
	var entitlement []byte
	var expiresAtNS int64
	if err := scanner.Scan(&result.id, &result.productID, &result.tenantID, &entitlement, &expiresAtNS, &result.maxClaims); err != nil {
		return codeRecord{}, err
	}
	result.expiresAt = nanoTime(expiresAtNS)
	value, err := unmarshalEntitlement(entitlement)
	if err != nil {
		return codeRecord{}, err
	}
	result.entitlement = value
	return result, nil
}

func readTicket(scanner rowScanner) (ticketRecord, error) {
	var result ticketRecord
	var expiresAtNS int64
	err := scanner.Scan(&result.codeID, &result.clientID, &result.productID, &result.tenantHint, &expiresAtNS)
	result.expiresAt = nanoTime(expiresAtNS)
	return result, err
}

func newContext(code codeRecord) *activation.AccountContext {
	return &activation.AccountContext{ProductID: code.productID, TenantID: code.tenantID, Entitlement: code.entitlement}
}

func (code codeRecord) available(now time.Time) bool {
	return code.expiresAt.IsZero() || now.Before(code.expiresAt)
}

func (ticket ticketRecord) available(now time.Time) bool { return now.Before(ticket.expiresAt) }

func marshalEntitlement(value *commerce.EntitlementSnapshot) ([]byte, error) {
	if value == nil {
		return nil, nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("tenantactivation/postgres: encode entitlement: %w", err)
	}
	return encoded, nil
}

func unmarshalEntitlement(encoded []byte) (*commerce.EntitlementSnapshot, error) {
	if len(encoded) == 0 || string(encoded) == "null" {
		return nil, nil
	}
	value := &commerce.EntitlementSnapshot{}
	if err := json.Unmarshal(encoded, value); err != nil {
		return nil, fmt.Errorf("tenantactivation/postgres: decode entitlement: %w", err)
	}
	return value, nil
}

func timeNano(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UnixNano()
}

func nanoTime(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(0, value).UTC()
}

var _ activation.Store = (*Store)(nil)
var _ activation.CodeProvisioner = (*Store)(nil)
