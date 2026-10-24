package permissioncatalog

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/domains/permissions/resourcecatalog"
)

type scanner interface{ Scan(...any) error }

func scan(s scanner) (*permissions.Resource, int, error) {
	var r permissions.Resource
	var auth, segments int
	var created, updated int64
	var attrs, required, method string
	var dispatch []byte
	err := s.Scan(&r.ID, &r.TenantID, &r.ClientID, &r.Type, &r.Name, &auth, &r.Description,
		&attrs, &required, &r.RequireMode, &created, &updated, &dispatch, &method, &segments)
	if err != nil {
		return nil, 0, err
	}
	if len(attrs)+len(required) > maxCatalogJSONBytes {
		return nil, 0, fmt.Errorf("permissions/postgres: resource JSON budget exceeded")
	}
	if attrs != "" && attrs != "null" {
		if err := json.Unmarshal([]byte(attrs), &r.Attributes); err != nil {
			return nil, 0, err
		}
	}
	if required != "" && required != "null" {
		if err := json.Unmarshal([]byte(required), &r.RequiredPermissions); err != nil {
			return nil, 0, err
		}
	}
	r.RequiresAuth = auth != 0
	r.CreatedAt, r.UpdatedAt = time.Unix(0, created).UTC(), time.Unix(0, updated).UTC()
	return &r, len(attrs) + len(required), nil
}

func (p *Catalog) GetResource(ctx context.Context, id string) (*permissions.Resource, error) {
	r, _, err := scan(p.db.QueryRowContext(ctx, "SELECT "+columns+" FROM permissions_resources WHERE id=$1", id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, permissions.ErrResourceNotFound
	}
	return r, err
}

func (p *Catalog) ListResources(ctx context.Context, tenant, client string) ([]*permissions.Resource, error) {
	return p.list(ctx, `SELECT `+columns+` FROM permissions_resources WHERE tenant_id=$1 AND client_id=$2 ORDER BY id COLLATE "C" LIMIT $3`, tenant, client, maxCatalogRows+1)
}

func (p *Catalog) ListAllResources(ctx context.Context, client string) ([]*permissions.Resource, error) {
	return p.list(ctx, `SELECT `+columns+` FROM permissions_resources WHERE client_id=$1 ORDER BY tenant_id COLLATE "C",id COLLATE "C" LIMIT $2`, client, maxCatalogRows+1)
}

func (p *Catalog) list(ctx context.Context, query string, args ...any) ([]*permissions.Resource, error) {
	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out, total := make([]*permissions.Resource, 0), 0
	for rows.Next() {
		r, size, err := scan(rows)
		if err != nil {
			return nil, err
		}
		if len(out) >= maxCatalogRows || size > maxCatalogJSONBytes-total {
			return nil, fmt.Errorf("permissions/postgres: complete catalog exceeds read budget")
		}
		total += size
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func resolveQuery(lookup permissions.ResourceLookup) (string, []any) {
	query := "SELECT " + columns + " FROM permissions_resources WHERE tenant_id=$1 AND client_id=$2 AND type=$3"
	args := []any{lookup.TenantID, lookup.ClientID, string(lookup.Type)}
	d := resourcecatalog.DispatchFor(lookup.Type, lookup.Match)
	switch lookup.Type {
	case permissions.ResourceTypeHTTPAPI:
		query += " AND dispatch_method=$4 AND dispatch_segments=$5"
		args = append(args, d.Method, d.Segments)
	case permissions.ResourceTypeGRPCAPI, permissions.ResourceTypeGraphQLAPI,
		permissions.ResourceTypePage, permissions.ResourceTypeJSFn, permissions.ResourceTypeUIElement:
		query += " AND dispatch_key=$4"
		args = append(args, []byte(d.Key))
	}
	return query + ` ORDER BY id COLLATE "C"`, args
}

func (p *Catalog) ResolveResource(ctx context.Context, lookup permissions.ResourceLookup) (*permissions.ResourceDecision, error) {
	query, args := resolveQuery(lookup)
	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	count, total := 0, 0
	for rows.Next() {
		r, size, err := scan(rows)
		if err != nil {
			return nil, err
		}
		count++
		if count > maxCatalogRows || size > maxCatalogJSONBytes-total {
			return nil, fmt.Errorf("permissions/postgres: resource resolution budget exceeded")
		}
		total += size
		if resourcecatalog.Matches(r, lookup.Match) {
			return resourcecatalog.Decision(r), nil
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &permissions.ResourceDecision{Found: false}, nil
}
