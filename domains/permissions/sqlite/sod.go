package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/yangwb1123/snaplink/domains/permissions"
)

const (
	staticSoDMode  = "static"
	dynamicSoDMode = "dynamic"
)

type rowQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// SetConflictSets replaces one client's static or dynamic conflict table in a
// single transaction. The delete-before-insert shape makes an empty request a
// durable clear and prevents readers from seeing a partial declaration.
func (p *Provider) SetConflictSets(ctx context.Context, clientID string, sets [][]string) error {
	return p.replaceConflictSets(ctx, clientID, staticSoDMode, sets)
}

func (p *Provider) ConflictSets(ctx context.Context, clientID string) ([][]string, error) {
	return p.loadConflictSets(ctx, p.db, clientID, staticSoDMode)
}

func (p *Provider) SetActivationConflictSets(ctx context.Context, clientID string, sets [][]string) error {
	return p.replaceConflictSets(ctx, clientID, dynamicSoDMode, sets)
}

func (p *Provider) ActivationConflictSets(ctx context.Context, clientID string) ([][]string, error) {
	return p.loadConflictSets(ctx, p.db, clientID, dynamicSoDMode)
}

func (p *Provider) replaceConflictSets(ctx context.Context, clientID, mode string, sets [][]string) error {
	if err := permissions.ValidateConflictSets(sets); err != nil {
		return err
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: begin conflict sets: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
        DELETE FROM permissions_conflict_sets WHERE client_id = ? AND mode = ?`, clientID, mode); err != nil {
		return fmt.Errorf("permissions/sqlite: clear conflict sets: %w", err)
	}
	for i, set := range sets {
		seen := make(map[string]struct{}, len(set))
		for _, code := range set {
			if _, ok := seen[code]; ok {
				continue
			}
			seen[code] = struct{}{}
			if _, err := tx.ExecContext(ctx, `
                INSERT INTO permissions_conflict_sets (client_id, mode, set_index, role_code)
                VALUES (?, ?, ?, ?)`, clientID, mode, i, code); err != nil {
				return fmt.Errorf("permissions/sqlite: store conflict set: %w", err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("permissions/sqlite: commit conflict sets: %w", err)
	}
	return nil
}

func (p *Provider) loadConflictSets(ctx context.Context, q rowQueryer, clientID, mode string) ([][]string, error) {
	rows, err := q.QueryContext(ctx, `
        SELECT set_index, role_code FROM permissions_conflict_sets
        WHERE client_id = ? AND mode = ? ORDER BY set_index, role_code`, clientID, mode)
	if err != nil {
		return nil, fmt.Errorf("permissions/sqlite: list conflict sets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out [][]string
	current := -1
	for rows.Next() {
		var index int
		var code string
		if err := rows.Scan(&index, &code); err != nil {
			return nil, fmt.Errorf("permissions/sqlite: scan conflict set: %w", err)
		}
		if index != current {
			out = append(out, nil)
			current = index
		}
		out[len(out)-1] = append(out[len(out)-1], code)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("permissions/sqlite: conflict set rows: %w", err)
	}
	return out, nil
}

func (p *Provider) checkStaticConflict(ctx context.Context, q rowQueryer, clientID string, roles []string) error {
	sets, err := p.loadConflictSets(ctx, q, clientID, staticSoDMode)
	if err != nil {
		return err
	}
	return permissions.CheckRoleConflict(clientID, sets, roles)
}

// ActivateRoles persists the session's active subset only after validating
// assignment ownership and both static and dynamic conflict declarations.
func (p *Provider) ActivateRoles(ctx context.Context, userID, clientID, sessionID string, roles []string) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: begin activation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if len(roles) > 0 {
		held, err := p.assignedCodes(ctx, tx, userID, clientID)
		if err != nil {
			return err
		}
		for _, code := range roles {
			if !containsCode(held, code) {
				return fmt.Errorf("%w: %q", permissions.ErrRoleNotAssigned, code)
			}
		}
	}
	static, err := p.loadConflictSets(ctx, tx, clientID, staticSoDMode)
	if err != nil {
		return err
	}
	dynamic, err := p.loadConflictSets(ctx, tx, clientID, dynamicSoDMode)
	if err != nil {
		return err
	}
	if conflict := permissions.CheckRoleConflict(clientID, append(static, dynamic...), roles); conflict != nil {
		return conflict
	}
	if _, err := tx.ExecContext(ctx, `
        DELETE FROM permissions_active_roles
        WHERE user_id = ? AND client_id = ? AND session_id = ?`, userID, clientID, sessionID); err != nil {
		return fmt.Errorf("permissions/sqlite: clear activation: %w", err)
	}
	for i, code := range roles {
		if _, err := tx.ExecContext(ctx, `
            INSERT INTO permissions_active_roles (user_id, client_id, session_id, role_code, role_index)
            VALUES (?, ?, ?, ?, ?)`, userID, clientID, sessionID, code, i); err != nil {
			return fmt.Errorf("permissions/sqlite: store activation: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("permissions/sqlite: commit activation: %w", err)
	}
	return nil
}

func (p *Provider) ActiveRoles(ctx context.Context, userID, clientID, sessionID string) ([]permissions.Role, error) {
	rows, err := p.db.QueryContext(ctx, `
        SELECT role_code FROM permissions_active_roles
        WHERE user_id = ? AND client_id = ? AND session_id = ? ORDER BY role_index`, userID, clientID, sessionID)
	if err != nil {
		return nil, fmt.Errorf("permissions/sqlite: list active roles: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var codes []string
	for rows.Next() {
		var code string
		if err := rows.Scan(&code); err != nil {
			return nil, fmt.Errorf("permissions/sqlite: scan active role: %w", err)
		}
		codes = append(codes, code)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("permissions/sqlite: active role rows: %w", err)
	}
	if len(codes) == 0 {
		return nil, nil
	}
	defs, err := p.ListAllRoles(ctx, clientID)
	if err != nil {
		return nil, err
	}
	byCode := make(map[string]permissions.Role, len(defs))
	for _, role := range defs {
		byCode[role.Code] = role
	}
	out := make([]permissions.Role, 0, len(codes))
	for _, code := range codes {
		if role, ok := byCode[code]; ok {
			out = append(out, role)
		}
	}
	return out, nil
}

func (p *Provider) DeactivateSession(ctx context.Context, userID, clientID, sessionID string) error {
	_, err := p.db.ExecContext(ctx, `
        DELETE FROM permissions_active_roles
        WHERE user_id = ? AND client_id = ? AND session_id = ?`, userID, clientID, sessionID)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: deactivate session: %w", err)
	}
	return nil
}

func (p *Provider) assignedCodes(ctx context.Context, q rowQueryer, userID, clientID string) ([]string, error) {
	var raw string
	row := q.QueryRowContext(ctx, `
        SELECT roles_json FROM permissions_assignments WHERE user_id = ? AND client_id = ?`, userID, clientID)
	if err := row.Scan(&raw); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%w: %q", permissions.ErrRoleNotAssigned, "")
		}
		return nil, fmt.Errorf("permissions/sqlite: load assigned roles: %w", err)
	}
	var roles []string
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &roles); err != nil {
			return nil, fmt.Errorf("permissions/sqlite: decode assigned roles: %w", err)
		}
	}
	return roles, nil
}

func containsCode(codes []string, want string) bool {
	for _, code := range codes {
		if code == want {
			return true
		}
	}
	return false
}

var (
	_ permissions.SoDProvider          = (*Provider)(nil)
	_ permissions.SessionRoleActivator = (*Provider)(nil)
)
