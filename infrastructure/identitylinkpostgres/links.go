package identitylinkpostgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/domains/identitylink"
)

// ListByUser implements identitylink.Store.
func (s *Store) ListByUser(ctx context.Context, userID string) ([]identitylink.Identity, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, user_id, provider, subject, status, linked_at, unlinked_at
FROM identity_links
WHERE user_id = $1 AND status = $2
ORDER BY linked_at, id`, userID, identitylink.StatusActive)
	if err != nil {
		return nil, fmt.Errorf("identitylink/postgres: list: %w", err)
	}
	defer rows.Close()
	var out []identitylink.Identity
	for rows.Next() {
		rec, err := scanIdentity(rows)
		if err != nil {
			return nil, fmt.Errorf("identitylink/postgres: list scan: %w", err)
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// Link implements identitylink.Store with a database-enforced unique active
// owner for every provider/subject pair.
func (s *Store) Link(ctx context.Context, userID, provider, subject string) (identitylink.Identity, error) {
	if err := identitylink.ValidateLinkInput(userID, provider, subject); err != nil {
		return identitylink.Identity{}, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		rec := identitylink.Identity{
			ID: newLinkID(), UserID: userID, Provider: provider, Subject: subject,
			Status: identitylink.StatusActive, LinkedAt: time.Now().UTC(),
		}
		result, err := s.db.ExecContext(ctx, `
INSERT INTO identity_links
    (id, user_id, provider, subject, status, linked_at, unlinked_at)
VALUES ($1, $2, $3, $4, $5, $6, 0)
ON CONFLICT DO NOTHING`,
			rec.ID, rec.UserID, rec.Provider, rec.Subject, rec.Status, rec.LinkedAt.UnixNano())
		if err != nil {
			return identitylink.Identity{}, fmt.Errorf("identitylink/postgres: link: %w", err)
		}
		if inserted, _ := result.RowsAffected(); inserted == 1 {
			return rec, nil
		}
		existing, found, err := s.FindByProviderSubject(ctx, provider, subject)
		if err != nil {
			return identitylink.Identity{}, err
		}
		if found {
			if existing.UserID == userID {
				return existing, nil
			}
			return identitylink.Identity{}, identitylink.ErrAccountConflict
		}
	}
	return identitylink.Identity{}, errors.New("identitylink/postgres: concurrent link changed repeatedly")
}

// Unlink implements identitylink.Store.
func (s *Store) Unlink(ctx context.Context, userID, id string) error {
	result, err := s.db.ExecContext(ctx, `
UPDATE identity_links
SET status = $1, unlinked_at = $2
WHERE id = $3 AND user_id = $4 AND status = $5`,
		identitylink.StatusRevoked, time.Now().UTC().UnixNano(),
		id, userID, identitylink.StatusActive)
	if err != nil {
		return fmt.Errorf("identitylink/postgres: unlink: %w", err)
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return identitylink.ErrNotFound
	}
	return nil
}

// FindByProviderSubject implements identitylink.Store.
func (s *Store) FindByProviderSubject(ctx context.Context, provider, subject string) (identitylink.Identity, bool, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, user_id, provider, subject, status, linked_at, unlinked_at
FROM identity_links
WHERE provider = $1 AND subject = $2 AND status = $3`,
		provider, subject, identitylink.StatusActive)
	rec, err := scanIdentity(row)
	if errors.Is(err, sql.ErrNoRows) {
		return identitylink.Identity{}, false, nil
	}
	if err != nil {
		return identitylink.Identity{}, false, fmt.Errorf("identitylink/postgres: find: %w", err)
	}
	return rec, true, nil
}

type identityScanner interface {
	Scan(dest ...any) error
}

func scanIdentity(scanner identityScanner) (identitylink.Identity, error) {
	var rec identitylink.Identity
	var linkedAt, unlinkedAt int64
	err := scanner.Scan(&rec.ID, &rec.UserID, &rec.Provider, &rec.Subject,
		&rec.Status, &linkedAt, &unlinkedAt)
	if err != nil {
		return identitylink.Identity{}, err
	}
	rec.LinkedAt = time.Unix(0, linkedAt).UTC()
	if unlinkedAt > 0 {
		rec.UnlinkedAt = time.Unix(0, unlinkedAt).UTC()
	}
	return rec, nil
}

func newLinkID() string {
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	return hex.EncodeToString(raw)
}
