package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

// roleStrip is a pending rewrite of one user's assignment row with a
// removed role code already filtered out.
type roleStrip struct {
	userID string
	roles  []string
}

// collectRoleStrips walks every assignment under clientID and returns
// the rows whose role list contains roleCode, with roleCode removed.
// The assignment table is per-client-indexed so this is a bounded
// scan. Rows are read fully before any write so the caller can drive
// the rewrites on the same transaction without an open cursor.
func collectRoleStrips(ctx context.Context, tx *sql.Tx, clientID, roleCode string) ([]roleStrip, error) {
	rows, err := tx.QueryContext(ctx, `
        SELECT user_id, roles_json FROM permissions_assignments WHERE client_id = ?`,
		clientID,
	)
	if err != nil {
		return nil, fmt.Errorf("permissions/sqlite: scan assignments: %w", err)
	}
	var updates []roleStrip
	for rows.Next() {
		var userID, rolesJSON string
		if err := rows.Scan(&userID, &rolesJSON); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("permissions/sqlite: scan assignment row: %w", err)
		}
		var roles []string
		if rolesJSON != "" {
			if err := json.Unmarshal([]byte(rolesJSON), &roles); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("permissions/sqlite: unmarshal assignment: %w", err)
			}
		}
		if filtered, dirty := filterRoleCode(roles, roleCode); dirty {
			updates = append(updates, roleStrip{userID: userID, roles: filtered})
		}
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("permissions/sqlite: assignment rows: %w", err)
	}
	return updates, nil
}

// filterRoleCode returns roles with roleCode removed plus whether any
// element was dropped.
func filterRoleCode(roles []string, roleCode string) ([]string, bool) {
	filtered := make([]string, 0, len(roles))
	dirty := false
	for _, r := range roles {
		if r == roleCode {
			dirty = true
			continue
		}
		filtered = append(filtered, r)
	}
	return filtered, dirty
}

// applyRoleStrips writes each pending assignment rewrite back on tx.
func applyRoleStrips(ctx context.Context, tx *sql.Tx, clientID string, updates []roleStrip) error {
	for _, u := range updates {
		raw, err := json.Marshal(u.roles)
		if err != nil {
			return fmt.Errorf("permissions/sqlite: marshal updated assignment: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
            UPDATE permissions_assignments SET roles_json = ?
            WHERE user_id = ? AND client_id = ?`,
			string(raw), u.userID, clientID,
		); err != nil {
			return fmt.Errorf("permissions/sqlite: strip assignment: %w", err)
		}
	}
	return nil
}

// stripRoleCodes returns have with every code in remove filtered out,
// preserving order. Codes in remove not present in have are ignored.
func stripRoleCodes(have, remove []string) []string {
	drop := make(map[string]struct{}, len(remove))
	for _, r := range remove {
		drop[r] = struct{}{}
	}
	filtered := make([]string, 0, len(have))
	for _, r := range have {
		if _, ok := drop[r]; ok {
			continue
		}
		filtered = append(filtered, r)
	}
	return filtered
}
