package tui

import "fmt"

// entityDescriptor is the single place that knows an entity type's admin API
// shape: list/create/item paths, the JSON envelope keys, how to render a
// list row, and how to build create/edit forms. listViewModel and formModel
// are otherwise entity-agnostic.
type entityDescriptor struct {
	Key      string // registry key, also used as the menu selection identity
	Label    string // menu label / list title, e.g. "Tenants"
	ListPath string
	ItemsKey string // envelope key for the list response, e.g. {"tenants": [...]}
	ItemKey  string // envelope key for a single-object response, e.g. {"tenant": {...}}
	ReadOnly bool   // true for clients: list/view only, n/e/d are no-ops

	Row func(item map[string]any) (id, title, desc string)

	CreateFields func() []fieldSpec
	EditFields   func(existing map[string]any) []fieldSpec

	CreatePath string
	ItemPath   func(id string) string // used for PUT (update) and DELETE
}

// genericItem adapts one decoded JSON record to list.DefaultItem. raw keeps
// the full decoded object so "e" can pre-fill an edit form without a second
// round-trip to the server.
type genericItem struct {
	id    string
	title string
	desc  string
	raw   map[string]any
}

func (i genericItem) FilterValue() string { return i.title }
func (i genericItem) Title() string       { return i.title }
func (i genericItem) Description() string { return i.desc }

// registry is the menu's fixed entity list, in display order.
var registry = []entityDescriptor{tenantDescriptor, userDescriptor, clientDescriptor}

var tenantDescriptor = entityDescriptor{
	Key:      "tenants",
	Label:    "Tenants",
	ListPath: "/api/v1/admin/tenants",
	ItemsKey: "tenants",
	ItemKey:  "tenant",

	Row:          tenantRow,
	CreateFields: tenantCreateFields,
	EditFields:   tenantEditFields,

	CreatePath: "/api/v1/admin/tenants",
	ItemPath:   func(id string) string { return "/api/v1/admin/tenants/" + id },
}

func tenantRow(item map[string]any) (id, title, desc string) {
	id = asString(item["id"])
	title = asString(item["name"])
	if title == "" {
		title = asString(item["slug"])
	}
	desc = fmt.Sprintf("slug=%s status=%s", asString(item["slug"]), asString(item["status"]))
	return id, title, desc
}

func tenantCreateFields() []fieldSpec {
	return []fieldSpec{
		{Key: "id", Label: "ID", Kind: kindText},
		{Key: "slug", Label: "Slug", Kind: kindText},
		{Key: "name", Label: "Name", Kind: kindText},
		{Key: "status", Label: "Status (active|suspended)", Kind: kindText, Initial: "active"},
		{Key: "home_region", Label: "Home Region", Kind: kindText},
		{Key: "allowed_regions", Label: "Allowed Regions (comma-separated)", Kind: kindCSV},
		{Key: "settings", Label: "Settings (key=value,key2=value2)", Kind: kindKV},
		{Key: "enforce_writes", Label: "Enforce Writes (true/false)", Kind: kindBool, Initial: "false"},
	}
}

// tenantEditFields omits "id" (immutable, addressed by the URL path) and
// "status" — the admin API ignores status on PUT; status transitions only
// happen through :set-status, which this TUI pass doesn't expose (see
// entitiescmd's set-status CLI verb for that).
func tenantEditFields(existing map[string]any) []fieldSpec {
	return []fieldSpec{
		{Key: "slug", Label: "Slug", Kind: kindText, Initial: asString(existing["slug"])},
		{Key: "name", Label: "Name", Kind: kindText, Initial: asString(existing["name"])},
		{Key: "home_region", Label: "Home Region", Kind: kindText, Initial: asString(existing["home_region"])},
		{Key: "allowed_regions", Label: "Allowed Regions (comma-separated)", Kind: kindCSV, Initial: joinCSV(existing["allowed_regions"])},
		{Key: "settings", Label: "Settings (key=value,key2=value2)", Kind: kindKV, Initial: joinKV(existing["settings"])},
		{Key: "enforce_writes", Label: "Enforce Writes (true/false)", Kind: kindBool, Initial: asBoolText(existing["enforce_writes"])},
	}
}

var userDescriptor = entityDescriptor{
	Key:      "users",
	Label:    "Users",
	ListPath: "/api/v1/admin/users",
	ItemsKey: "users",
	ItemKey:  "user",

	Row:          userRow,
	CreateFields: userCreateFields,
	EditFields:   userEditFields,

	CreatePath: "/api/v1/admin/users",
	ItemPath:   func(id string) string { return "/api/v1/admin/users/" + id },
}

func userRow(item map[string]any) (id, title, desc string) {
	id = asString(item["id"])
	title = asString(item["external_id"])
	if title == "" {
		title = id
	}
	desc = fmt.Sprintf("provider=%s", asString(item["provider"]))
	return id, title, desc
}

func userCreateFields() []fieldSpec {
	return []fieldSpec{
		{Key: "id", Label: "ID", Kind: kindText},
		{Key: "external_id", Label: "External ID", Kind: kindText},
		{Key: "provider", Label: "Provider", Kind: kindText},
		{Key: "attributes", Label: "Attributes (key=value,key2=value2)", Kind: kindKV},
	}
}

// userEditFields omits "id" for the same reason as tenants: immutable,
// addressed by the URL path.
func userEditFields(existing map[string]any) []fieldSpec {
	return []fieldSpec{
		{Key: "external_id", Label: "External ID", Kind: kindText, Initial: asString(existing["external_id"])},
		{Key: "provider", Label: "Provider", Kind: kindText, Initial: asString(existing["provider"])},
		{Key: "attributes", Label: "Attributes (key=value,key2=value2)", Kind: kindKV, Initial: joinKV(existing["attributes"])},
	}
}

// clientDescriptor has no CreateFields/EditFields/CreatePath — ReadOnly
// short-circuits n/e/d in listview.go before those would ever be used,
// matching the existing read-only clientscmd CLI.
var clientDescriptor = entityDescriptor{
	Key:      "clients",
	Label:    "Clients",
	ListPath: "/api/v1/admin/clients",
	ItemsKey: "clients",
	ItemKey:  "client",
	ReadOnly: true,

	Row: clientRow,
}

func clientRow(item map[string]any) (id, title, desc string) {
	id = asString(item["id"])
	title = asString(item["name"])
	desc = fmt.Sprintf("token_strategy=%s active=%s", asString(item["token_strategy"]), asBoolText(item["active"]))
	return id, title, desc
}
