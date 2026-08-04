package legacysync

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"

	_ "modernc.org/sqlite"
)

type targetUser struct {
	ID         string
	ExternalID string
	Provider   string
	Attributes map[string]string
	CreatedAt  int64
}

type targetSnapshot struct {
	Users       map[string]targetUser
	ExternalIDs map[string]string
	Roles       map[string]struct{}
	Assignments map[assignmentKey][]string
	Clients     map[string]struct{}
}

func openTarget(ctx context.Context, dsn string, readonly bool) (*sql.DB, error) {
	if readonly {
		dsn = readOnlyDSN(dsn)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("target open: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("target ping: %w", err)
	}
	return db, nil
}

func readOnlyDSN(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme != "file" {
		return dsn
	}
	query := u.Query()
	query.Del("_journal")
	query.Set("mode", "ro")
	u.RawQuery = query.Encode()
	return u.String()
}

func inspectTarget(ctx context.Context, db *sql.DB) (targetSnapshot, error) {
	if err := requireTables(ctx, db); err != nil {
		return targetSnapshot{}, err
	}
	s := targetSnapshot{Users: map[string]targetUser{}, ExternalIDs: map[string]string{},
		Roles: map[string]struct{}{}, Assignments: map[assignmentKey][]string{}, Clients: map[string]struct{}{}}
	if err := loadTargetUsers(ctx, db, &s); err != nil {
		return targetSnapshot{}, err
	}
	if err := loadTargetRoles(ctx, db, &s); err != nil {
		return targetSnapshot{}, err
	}
	if err := loadTargetAssignments(ctx, db, &s); err != nil {
		return targetSnapshot{}, err
	}
	if err := loadTargetClients(ctx, db, &s); err != nil {
		return targetSnapshot{}, err
	}
	return s, nil
}

func requireTables(ctx context.Context, db *sql.DB) error {
	required := []string{"users", "password_credentials", "permissions_roles", "permissions_assignments", "clients"}
	rows, err := db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		return fmt.Errorf("target schema query: %w", err)
	}
	defer func() { _ = rows.Close() }()
	have := map[string]struct{}{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return fmt.Errorf("target schema scan: %w", err)
		}
		have[name] = struct{}{}
	}
	for _, table := range required {
		if _, ok := have[table]; !ok {
			return fmt.Errorf("target schema missing table %s", table)
		}
	}
	return rows.Err()
}

func loadTargetUsers(ctx context.Context, db *sql.DB, s *targetSnapshot) error {
	rows, err := db.QueryContext(ctx, `SELECT id,COALESCE(external_id,''),COALESCE(provider,''),attributes,created_at FROM users`)
	if err != nil {
		return fmt.Errorf("target users query: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var user targetUser
		var raw string
		if err := rows.Scan(&user.ID, &user.ExternalID, &user.Provider, &raw, &user.CreatedAt); err != nil {
			return fmt.Errorf("target user scan: %w", err)
		}
		if raw != "" && raw != "null" {
			if err := json.Unmarshal([]byte(raw), &user.Attributes); err != nil {
				return fmt.Errorf("target user attributes: %w", err)
			}
		}
		s.Users[user.ID] = user
		if user.Provider == legacyProvider && user.ExternalID != "" {
			s.ExternalIDs[user.ExternalID] = user.ID
		}
	}
	return rows.Err()
}

func loadTargetRoles(ctx context.Context, db *sql.DB, s *targetSnapshot) error {
	rows, err := db.QueryContext(ctx, `SELECT client_id,role_code FROM permissions_roles`)
	if err != nil {
		return fmt.Errorf("target roles query: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var clientID, code string
		if err := rows.Scan(&clientID, &code); err != nil {
			return fmt.Errorf("target role scan: %w", err)
		}
		s.Roles[clientID+"\x00"+code] = struct{}{}
	}
	return rows.Err()
}

func loadTargetAssignments(ctx context.Context, db *sql.DB, s *targetSnapshot) error {
	rows, err := db.QueryContext(ctx, `SELECT user_id,client_id,roles_json FROM permissions_assignments`)
	if err != nil {
		return fmt.Errorf("target assignments query: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var key assignmentKey
		var raw string
		if err := rows.Scan(&key.UserID, &key.ClientID, &raw); err != nil {
			return fmt.Errorf("target assignment scan: %w", err)
		}
		var roles []string
		if err := json.Unmarshal([]byte(raw), &roles); err != nil {
			return fmt.Errorf("target assignment roles: %w", err)
		}
		s.Assignments[key] = roles
	}
	return rows.Err()
}

func loadTargetClients(ctx context.Context, db *sql.DB, s *targetSnapshot) error {
	rows, err := db.QueryContext(ctx, `SELECT id FROM clients WHERE active=1`)
	if err != nil {
		return fmt.Errorf("target clients query: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("target client scan: %w", err)
		}
		s.Clients[id] = struct{}{}
	}
	return rows.Err()
}

func buildReport(plan syncPlan, target targetSnapshot, mode string) (syncReport, error) {
	report := syncReport{Source: plan.Source, Credentials: len(plan.Users), Roles: len(plan.Roles),
		Assignments: len(plan.Assignments), Mode: mode}
	for clientID := range plan.MappedClients {
		if _, ok := target.Clients[clientID]; !ok {
			return syncReport{}, fmt.Errorf("mapped target client %q does not exist or is inactive", clientID)
		}
	}
	for _, user := range plan.Users {
		existing, ok := target.Users[user.ID]
		if ok && existing.Provider != legacyProvider {
			return syncReport{}, fmt.Errorf("target user id collision for %q", user.ID)
		}
		if id := target.ExternalIDs[user.ExternalID]; id != "" && id != user.ID {
			return syncReport{}, fmt.Errorf("target external id collision for legacy user %q", user.ID)
		}
		if ok {
			report.UpdateUsers++
		} else {
			report.CreateUsers++
		}
	}
	plannedIDs := map[string]struct{}{}
	for _, user := range plan.Users {
		plannedIDs[user.ID] = struct{}{}
	}
	for id, user := range target.Users {
		if user.Provider == legacyProvider {
			if _, ok := plannedIDs[id]; !ok && user.Attributes[activeAttr] != "false" {
				report.DeactivateUsers++
			}
		}
	}
	return report, validateMappedRoles(plan, target)
}

func validateMappedRoles(plan syncPlan, target targetSnapshot) error {
	planned := map[string]struct{}{}
	for _, role := range plan.Roles {
		planned[role.ClientID+"\x00"+role.Code] = struct{}{}
	}
	for key, codes := range plan.Assignments {
		for _, code := range codes {
			roleKey := key.ClientID + "\x00" + code
			if _, ok := planned[roleKey]; ok {
				continue
			}
			if _, ok := target.Roles[roleKey]; !ok {
				return fmt.Errorf("mapped target role %q is not defined for client %q", code, key.ClientID)
			}
		}
	}
	return nil
}

func applyPlan(ctx context.Context, db *sql.DB, plan syncPlan, target targetSnapshot) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("target begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := writeUsers(ctx, tx, plan, target); err != nil {
		return err
	}
	if err := writeRoles(ctx, tx, plan); err != nil {
		return err
	}
	if err := writeAssignments(ctx, tx, plan, target); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("target commit: %w", err)
	}
	return nil
}

func writeUsers(ctx context.Context, tx *sql.Tx, plan syncPlan, target targetSnapshot) error {
	plannedIDs := map[string]struct{}{}
	for _, user := range plan.Users {
		plannedIDs[user.ID] = struct{}{}
		existing := target.Users[user.ID]
		attrs := mergeAttributes(existing.Attributes, user.Attributes)
		raw, err := json.Marshal(attrs)
		if err != nil {
			return fmt.Errorf("target user attributes marshal: %w", err)
		}
		createdAt := user.CreatedAt.UnixNano()
		if existing.CreatedAt != 0 {
			createdAt = existing.CreatedAt
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO users
            (id,external_id,provider,email,name,attributes,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET external_id=excluded.external_id,
            provider=excluded.provider,email=excluded.email,name=excluded.name,
            attributes=excluded.attributes,updated_at=excluded.updated_at`, user.ID, user.ExternalID,
			legacyProvider, nullableString(user.Email), nullableString(user.Name), string(raw), createdAt, user.UpdatedAt.UnixNano()); err != nil {
			return fmt.Errorf("target user upsert: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO password_credentials (user_id,hash,updated_at)
            VALUES (?,?,?) ON CONFLICT(user_id) DO UPDATE SET hash=excluded.hash,updated_at=excluded.updated_at`,
			user.ID, user.Hash, user.UpdatedAt.UnixNano()); err != nil {
			return fmt.Errorf("target credential upsert: %w", err)
		}
	}
	return deactivateMissingUsers(ctx, tx, target, plannedIDs)
}

func deactivateMissingUsers(ctx context.Context, tx *sql.Tx, target targetSnapshot, planned map[string]struct{}) error {
	for id, user := range target.Users {
		if user.Provider != legacyProvider {
			continue
		}
		if _, ok := planned[id]; ok {
			continue
		}
		attrs := mergeAttributes(user.Attributes, map[string]string{activeAttr: "false"})
		raw, err := json.Marshal(attrs)
		if err != nil {
			return fmt.Errorf("target inactive attributes marshal: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET attributes=? WHERE id=?`, string(raw), id); err != nil {
			return fmt.Errorf("target user deactivate: %w", err)
		}
	}
	return nil
}

func writeRoles(ctx context.Context, tx *sql.Tx, plan syncPlan) error {
	for clientID, prefixes := range plan.ManagedPrefixes {
		for _, prefix := range prefixes {
			if _, err := tx.ExecContext(ctx, `DELETE FROM permissions_roles
                WHERE client_id=? AND substr(role_code,1,length(?))=?`, clientID, prefix, prefix); err != nil {
				return fmt.Errorf("target legacy role cleanup: %w", err)
			}
		}
	}
	for _, role := range plan.Roles {
		raw, err := json.Marshal(role.Permissions)
		if err != nil {
			return fmt.Errorf("target role permissions marshal: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO permissions_roles
            (client_id,role_code,name,description,permissions_json) VALUES (?,?,?,?,?)
            ON CONFLICT(client_id,role_code) DO UPDATE SET name=excluded.name,
            description=excluded.description,permissions_json=excluded.permissions_json`,
			role.ClientID, role.Code, role.Name, role.Description, string(raw)); err != nil {
			return fmt.Errorf("target role upsert: %w", err)
		}
	}
	return nil
}

func writeAssignments(ctx context.Context, tx *sql.Tx, plan syncPlan, target targetSnapshot) error {
	keys := map[assignmentKey]struct{}{}
	for key := range target.Assignments {
		if _, managed := plan.MappedClients[key.ClientID]; managed {
			keys[key] = struct{}{}
		}
	}
	for key := range plan.Assignments {
		keys[key] = struct{}{}
	}
	for key := range keys {
		roles := stripManaged(target.Assignments[key], plan.ManagedPrefixes[key.ClientID])
		roles = uniqueSorted(append(roles, plan.Assignments[key]...))
		if len(roles) == 0 {
			if _, err := tx.ExecContext(ctx, `DELETE FROM permissions_assignments WHERE user_id=? AND client_id=?`,
				key.UserID, key.ClientID); err != nil {
				return fmt.Errorf("target assignment delete: %w", err)
			}
			continue
		}
		raw, err := json.Marshal(roles)
		if err != nil {
			return fmt.Errorf("target assignment marshal: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO permissions_assignments (user_id,client_id,roles_json)
            VALUES (?,?,?) ON CONFLICT(user_id,client_id) DO UPDATE SET roles_json=excluded.roles_json`,
			key.UserID, key.ClientID, string(raw)); err != nil {
			return fmt.Errorf("target assignment upsert: %w", err)
		}
	}
	return nil
}

func mergeAttributes(existing, source map[string]string) map[string]string {
	out := make(map[string]string, len(existing)+len(source))
	for key, value := range existing {
		if !strings.HasPrefix(key, "sv_sso:") && key != activeAttr {
			out[key] = value
		}
	}
	for key, value := range source {
		out[key] = value
	}
	return out
}

func stripManaged(roles, prefixes []string) []string {
	out := make([]string, 0, len(roles))
	for _, role := range roles {
		managed := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(role, prefix) {
				managed = true
				break
			}
		}
		if !managed && !slices.Contains(out, role) {
			out = append(out, role)
		}
	}
	sort.Strings(out)
	return out
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
