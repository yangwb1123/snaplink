package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/domains/permissions"
)

const (
	staticSoDMode  = "static"
	dynamicSoDMode = "dynamic"
)

type permissionsQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (p *PermissionProvider) SetConflictSets(ctx context.Context, clientID string, sets [][]string) error {
	return p.replaceConflictSets(ctx, clientID, staticSoDMode, sets)
}

func (p *PermissionProvider) ConflictSets(ctx context.Context, clientID string) ([][]string, error) {
	return p.loadConflictSets(ctx, p.db, clientID, staticSoDMode)
}

func (p *PermissionProvider) SetActivationConflictSets(ctx context.Context, clientID string, sets [][]string) error {
	return p.replaceConflictSets(ctx, clientID, dynamicSoDMode, sets)
}

func (p *PermissionProvider) ActivationConflictSets(ctx context.Context, clientID string) ([][]string, error) {
	return p.loadConflictSets(ctx, p.db, clientID, dynamicSoDMode)
}

func (p *PermissionProvider) replaceConflictSets(ctx context.Context, clientID, mode string, sets [][]string) error {
	if err := permissions.ValidateConflictSets(sets); err != nil {
		return err
	}
	return runTx(ctx, p.db, serializable, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
            DELETE FROM permissions_conflict_sets WHERE client_id = $1 AND mode = $2`, clientID, mode); err != nil {
			return fmt.Errorf("postgres: clear conflict sets: %w", err)
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
                    VALUES ($1, $2, $3, $4)`, clientID, mode, i, code); err != nil {
					return fmt.Errorf("postgres: store conflict set: %w", err)
				}
			}
		}
		return nil
	})
}

func (p *PermissionProvider) loadConflictSets(ctx context.Context, q permissionsQueryer, clientID, mode string) ([][]string, error) {
	rows, err := q.QueryContext(ctx, `
        SELECT set_index, role_code FROM permissions_conflict_sets
        WHERE client_id = $1 AND mode = $2 ORDER BY set_index, role_code`, clientID, mode)
	if err != nil {
		return nil, fmt.Errorf("postgres: list conflict sets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out [][]string
	current := -1
	for rows.Next() {
		var index int
		var code string
		if err := rows.Scan(&index, &code); err != nil {
			return nil, fmt.Errorf("postgres: scan conflict set: %w", err)
		}
		if index != current {
			out = append(out, nil)
			current = index
		}
		out[len(out)-1] = append(out[len(out)-1], code)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: conflict set rows: %w", err)
	}
	return out, nil
}

func (p *PermissionProvider) checkStaticConflict(ctx context.Context, q permissionsQueryer, clientID string, roles []string) error {
	sets, err := p.loadConflictSets(ctx, q, clientID, staticSoDMode)
	if err != nil {
		return err
	}
	return permissions.CheckRoleConflict(clientID, sets, roles)
}

// ActivateRoles stores a session-scoped active role subset after checking the
// subject's assignment and both SSoD and DSoD declaration tables.
func (p *PermissionProvider) ActivateRoles(ctx context.Context, userID, clientID, sessionID string, roles []string) error {
	return runTx(ctx, p.db, serializable, func(tx *sql.Tx) error {
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
            WHERE user_id = $1 AND client_id = $2 AND session_id = $3`, userID, clientID, sessionID); err != nil {
			return fmt.Errorf("postgres: clear activation: %w", err)
		}
		for i, code := range roles {
			if _, err := tx.ExecContext(ctx, `
                INSERT INTO permissions_active_roles (user_id, client_id, session_id, role_code, role_index)
                VALUES ($1, $2, $3, $4, $5)`, userID, clientID, sessionID, code, i); err != nil {
				return fmt.Errorf("postgres: store activation: %w", err)
			}
		}
		return nil
	})
}

func (p *PermissionProvider) ActiveRoles(ctx context.Context, userID, clientID, sessionID string) ([]permissions.Role, error) {
	rows, err := p.db.QueryContext(ctx, `
        SELECT role_code FROM permissions_active_roles
        WHERE user_id = $1 AND client_id = $2 AND session_id = $3 ORDER BY role_index`, userID, clientID, sessionID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list active roles: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var codes []string
	for rows.Next() {
		var code string
		if err := rows.Scan(&code); err != nil {
			return nil, fmt.Errorf("postgres: scan active role: %w", err)
		}
		codes = append(codes, code)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: active role rows: %w", err)
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

func (p *PermissionProvider) DeactivateSession(ctx context.Context, userID, clientID, sessionID string) error {
	_, err := p.db.ExecContext(ctx, `
        DELETE FROM permissions_active_roles
        WHERE user_id = $1 AND client_id = $2 AND session_id = $3`, userID, clientID, sessionID)
	if err != nil {
		return fmt.Errorf("postgres: deactivate session: %w", err)
	}
	return nil
}

func (p *PermissionProvider) assignedCodes(ctx context.Context, q permissionsQueryer, userID, clientID string) ([]string, error) {
	var raw string
	row := q.QueryRowContext(ctx, `
        SELECT roles_json FROM permissions_assignments WHERE user_id = $1 AND client_id = $2`, userID, clientID)
	if err := row.Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %q", permissions.ErrRoleNotAssigned, "")
		}
		return nil, fmt.Errorf("postgres: load assigned roles: %w", err)
	}
	var roles []string
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &roles); err != nil {
			return nil, fmt.Errorf("postgres: decode assigned roles: %w", err)
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
