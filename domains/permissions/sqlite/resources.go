package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/domains/permissions"
)

type resourceRowScanner interface {
	Scan(dest ...any) error
}

const resourceColumns = `
    id, tenant_id, client_id, type, name, requires_auth,
    description, attributes_json, required_permissions_json,
    require_mode, created_at, updated_at, dispatch_key,
    dispatch_method, dispatch_segments`

// RegisterResource inserts or updates a catalog entry. The database's
// tuple constraint preserves the memory provider's conflict semantics.
func (p *Provider) RegisterResource(ctx context.Context, r *permissions.Resource) error {
	if r == nil {
		return permissions.ErrInvalidResource
	}
	if err := r.Validate(); err != nil {
		return err
	}
	attrs, required, err := marshalResource(r)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	created := r.CreatedAt
	if created.IsZero() {
		created = now
	}
	dispatch := resourceDispatch(r.Type, r.Attributes)
	_, err = p.db.ExecContext(ctx, `
        INSERT INTO permissions_resources (`+resourceColumns+`)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            tenant_id = excluded.tenant_id,
            client_id = excluded.client_id,
            type = excluded.type,
            name = excluded.name,
            requires_auth = excluded.requires_auth,
            description = excluded.description,
            attributes_json = excluded.attributes_json,
            required_permissions_json = excluded.required_permissions_json,
            require_mode = excluded.require_mode,
            updated_at = excluded.updated_at,
            dispatch_key = excluded.dispatch_key,
            dispatch_method = excluded.dispatch_method,
            dispatch_segments = excluded.dispatch_segments`,
		r.ID, r.TenantID, r.ClientID, string(r.Type), r.Name,
		boolInt(r.RequiresAuth), r.Description, attrs, required,
		string(r.RequireMode), created.UnixNano(), now.UnixNano(),
		dispatch.key, dispatch.method, dispatch.segments,
	)
	if err != nil {
		if isConstraintError(err) {
			return permissions.ErrResourceExists
		}
		return fmt.Errorf("permissions/sqlite: register resource: %w", err)
	}
	return nil
}

// GetResource returns one catalog entry by ID.
func (p *Provider) GetResource(ctx context.Context, id string) (*permissions.Resource, error) {
	row := p.db.QueryRowContext(ctx, `SELECT `+resourceColumns+`
        FROM permissions_resources WHERE id = ?`, id)
	r, err := scanResource(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, permissions.ErrResourceNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("permissions/sqlite: get resource: %w", err)
	}
	return r, nil
}

// ListResources returns entries in stable ID order for one scope.
func (p *Provider) ListResources(ctx context.Context, tenantID, clientID string) ([]*permissions.Resource, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT `+resourceColumns+`
        FROM permissions_resources
        WHERE tenant_id = ? AND client_id = ? ORDER BY id`, tenantID, clientID)
	if err != nil {
		return nil, fmt.Errorf("permissions/sqlite: list resources: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*permissions.Resource, 0)
	for rows.Next() {
		r, err := scanResource(rows)
		if err != nil {
			return nil, fmt.Errorf("permissions/sqlite: scan resource: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("permissions/sqlite: resource rows: %w", err)
	}
	return out, nil
}

// ListAllResources returns every catalog entry for clientID, including
// tenant-specific rows used by the client-wide policy bundle export.
func (p *Provider) ListAllResources(ctx context.Context, clientID string) ([]*permissions.Resource, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT `+resourceColumns+`
        FROM permissions_resources
        WHERE client_id = ? ORDER BY tenant_id, id`, clientID)
	if err != nil {
		return nil, fmt.Errorf("permissions/sqlite: list all resources: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*permissions.Resource, 0)
	for rows.Next() {
		r, err := scanResource(rows)
		if err != nil {
			return nil, fmt.Errorf("permissions/sqlite: scan resource: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("permissions/sqlite: resource rows: %w", err)
	}
	return out, nil
}

// DeleteResource removes a catalog entry and is intentionally idempotent.
func (p *Provider) DeleteResource(ctx context.Context, id string) error {
	if _, err := p.db.ExecContext(ctx, `DELETE FROM permissions_resources WHERE id = ?`, id); err != nil {
		return fmt.Errorf("permissions/sqlite: delete resource: %w", err)
	}
	return nil
}

// ResolveResource narrows candidates in SQL, then applies the same matcher
// as the memory backend so parameterized HTTP paths retain their semantics.
func (p *Provider) ResolveResource(ctx context.Context, lookup permissions.ResourceLookup) (*permissions.ResourceDecision, error) {
	query, args := resourceResolveQuery(lookup)
	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("permissions/sqlite: resolve resource: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		r, err := scanResource(rows)
		if err != nil {
			return nil, fmt.Errorf("permissions/sqlite: scan resolved resource: %w", err)
		}
		if resourceMatches(r, lookup.Match) {
			return resourceDecision(r), nil
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("permissions/sqlite: resolved resource rows: %w", err)
	}
	return &permissions.ResourceDecision{Found: false}, nil
}

func marshalResource(r *permissions.Resource) (string, string, error) {
	attrs, err := json.Marshal(r.Attributes)
	if err != nil {
		return "", "", fmt.Errorf("permissions/sqlite: marshal resource attributes: %w", err)
	}
	required, err := json.Marshal(r.RequiredPermissions)
	if err != nil {
		return "", "", fmt.Errorf("permissions/sqlite: marshal resource permissions: %w", err)
	}
	return string(attrs), string(required), nil
}

func scanResource(s resourceRowScanner) (*permissions.Resource, error) {
	var (
		r                       permissions.Resource
		typeName                string
		requiresAuth            int
		attrsJSON, requiredJSON string
		createdNS, updatedNS    int64
		dispatchKey             string
		dispatchMethod          string
		dispatchSegments        int
	)
	err := s.Scan(&r.ID, &r.TenantID, &r.ClientID, &typeName, &r.Name,
		&requiresAuth, &r.Description, &attrsJSON, &requiredJSON,
		&r.RequireMode, &createdNS, &updatedNS, &dispatchKey,
		&dispatchMethod, &dispatchSegments)
	if err != nil {
		return nil, err
	}
	r.Type = permissions.ResourceType(typeName)
	r.RequiresAuth = requiresAuth != 0
	r.CreatedAt = time.Unix(0, createdNS).UTC()
	r.UpdatedAt = time.Unix(0, updatedNS).UTC()
	if err := unmarshalResourceJSON(&r, attrsJSON, requiredJSON); err != nil {
		return nil, err
	}
	return &r, nil
}

func unmarshalResourceJSON(r *permissions.Resource, attrsJSON, requiredJSON string) error {
	if attrsJSON != "" && attrsJSON != "null" {
		if err := json.Unmarshal([]byte(attrsJSON), &r.Attributes); err != nil {
			return fmt.Errorf("permissions/sqlite: unmarshal resource attributes: %w", err)
		}
	}
	if requiredJSON != "" && requiredJSON != "null" {
		if err := json.Unmarshal([]byte(requiredJSON), &r.RequiredPermissions); err != nil {
			return fmt.Errorf("permissions/sqlite: unmarshal resource permissions: %w", err)
		}
	}
	return nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func isConstraintError(err error) bool {
	message := strings.ToUpper(err.Error())
	return strings.Contains(message, "UNIQUE") || strings.Contains(message, "PRIMARY KEY")
}
