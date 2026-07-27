package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yangwb1123/snaplink/domains/permissions"
)

// --- Role CRUD ---

// AddRole inserts a role. Returns [permissions.ErrRoleExists] when
// the (client_id, role_code) PK collides — matches the memory
// peer's contract so admin RPCs translate uniformly.
func (p *Provider) AddRole(ctx context.Context, clientID string, role permissions.Role) error {
	perms, err := json.Marshal(role.Permissions)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: marshal permissions: %w", err)
	}
	_, err = p.db.ExecContext(ctx, `
        INSERT INTO permissions_roles (client_id, role_code, name, description, permissions_json)
        VALUES (?, ?, ?, ?, ?)`,
		clientID, role.Code, role.Name, role.Description, string(perms),
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "PRIMARY KEY") {
			return permissions.ErrRoleExists
		}
		return fmt.Errorf("permissions/sqlite: insert role: %w", err)
	}
	return nil
}

// UpdateRole overwrites an existing role. Returns
// [permissions.ErrRoleNotFound] when the role doesn't exist —
// the SQL UPDATE with RowsAffected = 0 surfaces as the sentinel
// (not a silent no-op the memory peer would have produced via the
// in-memory check).
func (p *Provider) UpdateRole(ctx context.Context, clientID string, role permissions.Role) error {
	perms, err := json.Marshal(role.Permissions)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: marshal permissions: %w", err)
	}
	res, err := p.db.ExecContext(ctx, `
        UPDATE permissions_roles
        SET name = ?, description = ?, permissions_json = ?
        WHERE client_id = ? AND role_code = ?`,
		role.Name, role.Description, string(perms),
		clientID, role.Code,
	)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: update role: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("permissions/sqlite: update role rowsaffected: %w", err)
	}
	if n == 0 {
		return permissions.ErrRoleNotFound
	}
	return nil
}

// RemoveRole drops the role definition AND strips it from every
// user's assignment list under the same client. The strip is
// done row-by-row because SQLite has no native JSON array filter
// (and the typical assignment row holds <10 codes so a load /
// rewrite cycle is fine). Wrapped in a transaction so concurrent
// readers don't see a partial state.
func (p *Provider) RemoveRole(ctx context.Context, clientID, roleCode string) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: begin remove role: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, `
        DELETE FROM permissions_roles WHERE client_id = ? AND role_code = ?`,
		clientID, roleCode,
	)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: delete role: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("permissions/sqlite: delete role rowsaffected: %w", err)
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

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("permissions/sqlite: commit remove role: %w", err)
	}
	return nil
}

// ListAllRoles returns every role under clientID.
func (p *Provider) ListAllRoles(ctx context.Context, clientID string) ([]permissions.Role, error) {
	rows, err := p.db.QueryContext(ctx, `
        SELECT role_code, name, description, permissions_json
        FROM permissions_roles WHERE client_id = ? ORDER BY role_code`,
		clientID,
	)
	if err != nil {
		return nil, fmt.Errorf("permissions/sqlite: list roles: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []permissions.Role
	for rows.Next() {
		var code, name, description, permsJSON string
		if err := rows.Scan(&code, &name, &description, &permsJSON); err != nil {
			return nil, fmt.Errorf("permissions/sqlite: scan role: %w", err)
		}
		r := permissions.Role{Code: code, Name: name, Description: description}
		if permsJSON != "" && permsJSON != "[]" {
			if err := json.Unmarshal([]byte(permsJSON), &r.Permissions); err != nil {
				return nil, fmt.Errorf("permissions/sqlite: unmarshal role permissions: %w", err)
			}
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("permissions/sqlite: role rows: %w", err)
	}
	if out == nil {
		out = []permissions.Role{}
	}
	return out, nil
}
