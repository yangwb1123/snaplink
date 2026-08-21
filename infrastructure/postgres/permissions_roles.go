package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/yangwb1123/snaplink/domains/permissions"
)

// --- Role CRUD ---

// AddRole inserts a role. Returns [permissions.ErrRoleExists] when the
// (client_id, role_code) PK collides — the SQLSTATE 23505 detection via
// isUniqueViolation replaces the SQLite peer's error-string match.
func (p *PermissionProvider) AddRole(ctx context.Context, clientID string, role permissions.Role) error {
	perms, err := json.Marshal(role.Permissions)
	if err != nil {
		return fmt.Errorf("postgres: marshal permissions: %w", err)
	}
	_, err = p.db.ExecContext(ctx, `
        INSERT INTO permissions_roles (client_id, role_code, name, description, permissions_json)
        VALUES ($1, $2, $3, $4, $5)`,
		clientID, role.Code, role.Name, role.Description, string(perms),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return permissions.ErrRoleExists
		}
		return fmt.Errorf("postgres: insert role: %w", err)
	}
	return nil
}

// UpdateRole overwrites an existing role. Returns
// [permissions.ErrRoleNotFound] when the role doesn't exist (RowsAffected == 0).
func (p *PermissionProvider) UpdateRole(ctx context.Context, clientID string, role permissions.Role) error {
	perms, err := json.Marshal(role.Permissions)
	if err != nil {
		return fmt.Errorf("postgres: marshal permissions: %w", err)
	}
	res, err := p.db.ExecContext(ctx, `
        UPDATE permissions_roles
        SET name = $1, description = $2, permissions_json = $3
        WHERE client_id = $4 AND role_code = $5`,
		role.Name, role.Description, string(perms),
		clientID, role.Code,
	)
	if err != nil {
		return fmt.Errorf("postgres: update role: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres: update role rowsaffected: %w", err)
	}
	if n == 0 {
		return permissions.ErrRoleNotFound
	}
	return nil
}

// RemoveRole drops the role definition AND strips it from every user's
// assignment list under the same client. The strip loads / rewrites each
// affected assignment row (no native JSON array filter is used so the path
// stays identical to the SQLite peer). Wrapped in a transaction so concurrent
// readers never see a partial state.
func (p *PermissionProvider) RemoveRole(ctx context.Context, clientID, roleCode string) error {
	// SERIALIZABLE + 40001 retry (runTx): the delete-then-strip below reads and
	// rewrites every affected assignment row, a read-modify-write that would
	// race a concurrent grant under plain Postgres READ COMMITTED and 500 under
	// CockroachDB without the retry.
	return runTx(ctx, p.db, serializable, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
        DELETE FROM permissions_roles WHERE client_id = $1 AND role_code = $2`,
			clientID, roleCode,
		)
		if err != nil {
			return fmt.Errorf("postgres: delete role: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("postgres: delete role rowsaffected: %w", err)
		}
		if n == 0 {
			return permissions.ErrRoleNotFound
		}

		updates, err := collectRoleStrips(ctx, tx, clientID, roleCode)
		if err != nil {
			return err
		}
		if err := applyRoleStrips(ctx, tx, clientID, updates); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
            DELETE FROM permissions_active_roles WHERE client_id = $1 AND role_code = $2`, clientID, roleCode); err != nil {
			return fmt.Errorf("postgres: strip active role: %w", err)
		}
		return nil
	})
}

// ListAllRoles returns every role under clientID.
func (p *PermissionProvider) ListAllRoles(ctx context.Context, clientID string) ([]permissions.Role, error) {
	rows, err := p.db.QueryContext(ctx, `
        SELECT role_code, name, description, permissions_json
        FROM permissions_roles WHERE client_id = $1 ORDER BY role_code`,
		clientID,
	)
	if err != nil {
		return nil, fmt.Errorf("postgres: list roles: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []permissions.Role
	for rows.Next() {
		var code, name, description, permsJSON string
		if err := rows.Scan(&code, &name, &description, &permsJSON); err != nil {
			return nil, fmt.Errorf("postgres: scan role: %w", err)
		}
		r := permissions.Role{Code: code, Name: name, Description: description}
		if permsJSON != "" && permsJSON != "[]" {
			if err := json.Unmarshal([]byte(permsJSON), &r.Permissions); err != nil {
				return nil, fmt.Errorf("postgres: unmarshal role permissions: %w", err)
			}
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: role rows: %w", err)
	}
	if out == nil {
		out = []permissions.Role{}
	}
	return out, nil
}
