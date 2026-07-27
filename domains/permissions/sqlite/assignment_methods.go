package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/domains/permissions"
)

// --- Assignments ---

// AssignRoles replaces the user's role set under clientID. The
// memory peer treats this as a SET (not merge); same here.
func (p *Provider) AssignRoles(ctx context.Context, userID, clientID string, roles []string) error {
	if roles == nil {
		roles = []string{}
	}
	raw, err := json.Marshal(roles)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: marshal assignment: %w", err)
	}
	_, err = p.db.ExecContext(ctx, `
        INSERT INTO permissions_assignments (user_id, client_id, roles_json)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id, client_id) DO UPDATE SET roles_json = excluded.roles_json`,
		userID, clientID, string(raw),
	)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: assign roles: %w", err)
	}
	return nil
}

// UnassignRoles removes the listed role codes from the user's
// assignment under clientID. Codes not currently assigned are
// silently ignored (matches the memory peer).
func (p *Provider) UnassignRoles(ctx context.Context, userID, clientID string, roles []string) error {
	if len(roles) == 0 {
		return nil
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: begin unassign: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var current string
	row := tx.QueryRowContext(ctx, `
        SELECT roles_json FROM permissions_assignments
        WHERE user_id = ? AND client_id = ?`,
		userID, clientID,
	)
	if err := row.Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("permissions/sqlite: load assignment: %w", err)
	}
	var have []string
	if current != "" {
		if err := json.Unmarshal([]byte(current), &have); err != nil {
			return fmt.Errorf("permissions/sqlite: unmarshal assignment: %w", err)
		}
	}
	filtered := stripRoleCodes(have, roles)
	if len(filtered) == len(have) {
		// No change — skip the write to avoid the transaction
		// commit overhead.
		return tx.Commit()
	}
	raw, err := json.Marshal(filtered)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: marshal filtered assignment: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
        UPDATE permissions_assignments SET roles_json = ?
        WHERE user_id = ? AND client_id = ?`,
		string(raw), userID, clientID,
	); err != nil {
		return fmt.Errorf("permissions/sqlite: store filtered assignment: %w", err)
	}
	return tx.Commit()
}

// AddRoleToUser grants roleCode to userID under clientID without
// disturbing the user's other roles. Idempotent: re-adding an already-
// held role is a no-op. Implements [permissions.GroupMembershipWriter]
// (SCIM Group add-member). The load-append-store runs inside one
// transaction so a concurrent membership write can't lose this grant —
// the memory peer holds its mutex for the same window.
func (p *Provider) AddRoleToUser(ctx context.Context, userID, clientID, roleCode string) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: begin add role to user: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var current string
	row := tx.QueryRowContext(ctx, `
        SELECT roles_json FROM permissions_assignments
        WHERE user_id = ? AND client_id = ?`,
		userID, clientID,
	)
	if err := row.Scan(&current); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("permissions/sqlite: load assignment: %w", err)
	}
	var have []string
	if current != "" {
		if err := json.Unmarshal([]byte(current), &have); err != nil {
			return fmt.Errorf("permissions/sqlite: unmarshal assignment: %w", err)
		}
	}
	for _, r := range have {
		if r == roleCode {
			// Already a member — no write, just close the txn cleanly.
			return tx.Commit()
		}
	}
	have = append(have, roleCode)
	raw, err := json.Marshal(have)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: marshal assignment: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
        INSERT INTO permissions_assignments (user_id, client_id, roles_json)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id, client_id) DO UPDATE SET roles_json = excluded.roles_json`,
		userID, clientID, string(raw),
	); err != nil {
		return fmt.Errorf("permissions/sqlite: store assignment: %w", err)
	}
	return tx.Commit()
}

// RemoveRoleFromUser revokes roleCode from userID under clientID, leaving
// the user's other roles intact. Idempotent: removing a role the user
// doesn't hold is a no-op. Implements
// [permissions.GroupMembershipWriter] (SCIM Group remove-member). This is
// the single-code peer of UnassignRoles, kept distinct so the extension
// interface reads symmetrically with AddRoleToUser.
func (p *Provider) RemoveRoleFromUser(ctx context.Context, userID, clientID, roleCode string) error {
	return p.UnassignRoles(ctx, userID, clientID, []string{roleCode})
}

// ListAssignments returns every (user, []roleCodes) tuple under
// clientID with at least one role.
func (p *Provider) ListAssignments(ctx context.Context, clientID string) ([]permissions.Assignment, error) {
	rows, err := p.db.QueryContext(ctx, `
        SELECT user_id, roles_json FROM permissions_assignments WHERE client_id = ?
        ORDER BY user_id`,
		clientID,
	)
	if err != nil {
		return nil, fmt.Errorf("permissions/sqlite: list assignments: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]permissions.Assignment, 0)
	for rows.Next() {
		var userID, rolesJSON string
		if err := rows.Scan(&userID, &rolesJSON); err != nil {
			return nil, fmt.Errorf("permissions/sqlite: scan assignment: %w", err)
		}
		var roles []string
		if rolesJSON != "" {
			if err := json.Unmarshal([]byte(rolesJSON), &roles); err != nil {
				return nil, fmt.Errorf("permissions/sqlite: unmarshal assignment: %w", err)
			}
		}
		if len(roles) == 0 {
			continue
		}
		out = append(out, permissions.Assignment{UserID: userID, Roles: roles})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("permissions/sqlite: assignment rows: %w", err)
	}
	return out, nil
}
