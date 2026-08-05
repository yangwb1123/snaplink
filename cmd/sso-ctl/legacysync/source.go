package legacysync

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	mysql "github.com/go-sql-driver/mysql"
)

func loadLegacyData(ctx context.Context, cfg commandConfig, password string) (legacyData, error) {
	db, err := openLegacyDB(ctx, cfg, password)
	if err != nil {
		return legacyData{}, err
	}
	defer func() { _ = db.Close() }()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return legacyData{}, fmt.Errorf("legacy source begin read-only transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	data := legacyData{}
	if data.Users, err = loadUsers(ctx, tx); err != nil {
		return legacyData{}, err
	}
	if data.Roles, err = loadRoles(ctx, tx); err != nil {
		return legacyData{}, err
	}
	if err := loadRolePermissions(ctx, tx, data.Roles); err != nil {
		return legacyData{}, err
	}
	if data.Grants, err = loadGrants(ctx, tx); err != nil {
		return legacyData{}, err
	}
	if data.Overrides, err = loadOverrides(ctx, tx); err != nil {
		return legacyData{}, err
	}
	return data, tx.Commit()
}

func openLegacyDB(ctx context.Context, cfg commandConfig, password string) (*sql.DB, error) {
	mc := mysql.NewConfig()
	mc.User = cfg.SourceUser
	mc.Passwd = password
	mc.Net = "tcp"
	mc.Addr = cfg.SourceAddress
	mc.DBName = "sv_sso"
	mc.ParseTime = true
	mc.Loc = time.Local
	mc.TLSConfig = cfg.SourceTLS
	mc.Timeout = 5 * time.Second
	mc.ReadTimeout = 30 * time.Second
	mc.WriteTimeout = 5 * time.Second
	db, err := sql.Open("mysql", mc.FormatDSN())
	if err != nil {
		return nil, fmt.Errorf("legacy source open: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("legacy source ping: %w", err)
	}
	return db, nil
}

func loadUsers(ctx context.Context, q queryer) ([]legacyUser, error) {
	rows, err := q.QueryContext(ctx, `SELECT CAST(id AS CHAR), BIN_TO_UUID(uuid), login_id, password,
        COALESCE(name,''), COALESCE(email,''), COALESCE(avatar,''), CAST(gender AS CHAR),
        COALESCE(lang,''), COALESCE(CAST(home_path AS CHAR),''), status, created_at, updated_at
        FROM sv_sso.users ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("legacy users query: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []legacyUser
	for rows.Next() {
		var u legacyUser
		if err := rows.Scan(&u.LegacyID, &u.UUID, &u.LoginID, &u.Hash, &u.Name, &u.Email,
			&u.Avatar, &u.Gender, &u.Lang, &u.HomePath, &u.Status, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("legacy user scan: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func loadRoles(ctx context.Context, q queryer) ([]legacyRole, error) {
	rows, err := q.QueryContext(ctx, `SELECT a.code, CAST(r.id AS CHAR), CAST(r.pid AS CHAR),
        r.code, r.name, r.status FROM sv_auth.roles r
        JOIN sv_sso.applications a ON a.id=r.application_id ORDER BY a.code,r.id`)
	if err != nil {
		return nil, fmt.Errorf("legacy roles query: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []legacyRole
	for rows.Next() {
		var role legacyRole
		if err := rows.Scan(&role.AppCode, &role.ID, &role.ParentID, &role.Code, &role.Name, &role.Status); err != nil {
			return nil, fmt.Errorf("legacy role scan: %w", err)
		}
		out = append(out, role)
	}
	return out, rows.Err()
}

func loadRolePermissions(ctx context.Context, q queryer, roles []legacyRole) error {
	byID := make(map[string]*legacyRole, len(roles))
	for i := range roles {
		byID[roles[i].AppCode+":"+roles[i].ID] = &roles[i]
	}
	rows, err := q.QueryContext(ctx, `SELECT a.code, CAST(rm.role_id AS CHAR), CAST(rm.menu_id AS CHAR),
        COALESCE(ac.code,'') FROM sv_auth.role_menu rm
        JOIN sv_sso.applications a ON a.id=rm.application_id
        LEFT JOIN sv_auth.action_menu am ON am.application_id=rm.application_id
          AND am.menu_id=rm.menu_id AND am.status=1
        LEFT JOIN sv_auth.actions ac ON ac.id=am.action_id AND ac.status=1
        WHERE rm.status=1 ORDER BY a.code,rm.role_id,rm.menu_id,ac.code`)
	if err != nil {
		return fmt.Errorf("legacy role permissions query: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var app, roleID, menuID, action string
		if err := rows.Scan(&app, &roleID, &menuID, &action); err != nil {
			return fmt.Errorf("legacy role permission scan: %w", err)
		}
		role := byID[app+":"+roleID]
		if role == nil {
			return fmt.Errorf("legacy role permission references unknown role %s/%s", app, roleID)
		}
		role.Permissions = append(role.Permissions, menuPermission(menuID, "view"))
		if action != "" {
			role.Permissions = append(role.Permissions, menuPermission(menuID, strings.ToLower(action)))
		}
	}
	return rows.Err()
}

func loadGrants(ctx context.Context, q queryer) ([]legacyGrant, error) {
	rows, err := q.QueryContext(ctx, `SELECT a.code,u.login_id,CAST(ru.role_id AS CHAR),CAST(ru.id AS CHAR)
        FROM sv_auth.role_user ru JOIN sv_sso.applications a ON a.id=ru.application_id
        JOIN sv_sso.users u ON u.id=ru.user_id WHERE ru.status=1 ORDER BY a.code,u.login_id,ru.role_id`)
	if err != nil {
		return nil, fmt.Errorf("legacy grants query: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []legacyGrant
	for rows.Next() {
		var grant legacyGrant
		if err := rows.Scan(&grant.AppCode, &grant.LoginID, &grant.RoleID, &grant.RoleRowID); err != nil {
			return nil, fmt.Errorf("legacy grant scan: %w", err)
		}
		out = append(out, grant)
	}
	return out, rows.Err()
}

func loadOverrides(ctx context.Context, q queryer) ([]legacyOverride, error) {
	rows, err := q.QueryContext(ctx, `SELECT a.code,u.login_id,CAST(ru.id AS CHAR),CAST(ac.id AS CHAR),
        ac.code,COALESCE(CAST(am.menu_id AS CHAR),'') FROM sv_auth.role_user__action rua
        JOIN sv_auth.role_user ru ON ru.id=rua.role_user_id
        JOIN sv_sso.applications a ON a.id=rua.application_id
        JOIN sv_sso.users u ON u.id=ru.user_id JOIN sv_auth.actions ac ON ac.id=rua.action_id
        LEFT JOIN sv_auth.action_menu am ON am.application_id=rua.application_id
          AND am.action_id=rua.action_id AND am.status=1 WHERE rua.status=1
        ORDER BY a.code,u.login_id,ru.id,ac.id,am.menu_id`)
	if err != nil {
		return nil, fmt.Errorf("legacy overrides query: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []legacyOverride
	for rows.Next() {
		var override legacyOverride
		if err := rows.Scan(&override.AppCode, &override.LoginID, &override.RoleRowID,
			&override.ActionID, &override.Action, &override.MenuID); err != nil {
			return nil, fmt.Errorf("legacy override scan: %w", err)
		}
		out = append(out, override)
	}
	return out, rows.Err()
}

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}
