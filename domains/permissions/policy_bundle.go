package permissions

import (
	"context"
	"sort"
	"strings"
	"time"
)

// PolicyBundleVersion is the schema version of the exported bundle. A
// sidecar branches on it so a future incompatible shape can ship without
// silently breaking existing enforcers. Bump only on a breaking change.
const PolicyBundleVersion = 2

// PolicyBundle is the portable authorization-policy export a service-mesh
// sidecar (OPA/Cedar/custom) pulls to enforce authorization LOCALLY,
// without a per-request Authorizer RPC back to the SSO server.
//
// It carries role definitions, resource semantics, and client-wide SoD
// declarations, but NOT per-subject role assignments: a
// sidecar already has the caller's roles from the token (the SSO server
// embeds them when WithEmbedPermissionsInLogin is set), so the assignment
// half of the model never needs to leave the server. Shipping assignments
// would bloat the bundle to O(users) and leak the whole directory.
//
// The bundle is the data; WildcardSemantics is the rule set an enforcer
// must implement to match the server's permissions.Matches exactly (see
// docs/examples/opa-authz-policy.rego for a reference implementation).
type PolicyBundle struct {
	Version int `json:"version"`
	// GeneratedAt is informational only (when the export was rendered). It
	// is NOT part of the ETag-hashed content — see CanonicalBytes — so the
	// same roles produce the same ETag across regenerations regardless of
	// when each was built.
	GeneratedAt       time.Time         `json:"generated_at"`
	ClientID          string            `json:"client_id"`
	Roles             []RoleBundle      `json:"roles"`
	Resources         []ResourceBundle  `json:"resources"`
	SSoDConflictSets  [][]string        `json:"ssod_conflict_sets"`
	DSoDConflictSets  [][]string        `json:"dsod_conflict_sets"`
	WildcardSemantics WildcardSemantics `json:"wildcard_semantics"`
}

// RoleBundle is one role definition in the bundle: a role code plus the
// flat list of permission codes it grants. Name/Description are carried
// for operator-facing tooling (a sidecar matches on Code + Permissions).
type RoleBundle struct {
	Code        string   `json:"code"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions"`
}

// ResourceBundle is the decision-relevant projection of a catalog resource.
// Timestamps are intentionally excluded: they describe storage history, not
// authorization semantics, and must not churn a sidecar ETag.
type ResourceBundle struct {
	ID                  string            `json:"id"`
	TenantID            string            `json:"tenant_id,omitempty"`
	ClientID            string            `json:"client_id,omitempty"`
	Type                ResourceType      `json:"type"`
	Name                string            `json:"name"`
	RequiresAuth        bool              `json:"requires_auth"`
	Description         string            `json:"description,omitempty"`
	Attributes          map[string]string `json:"attributes,omitempty"`
	RequiredPermissions []string          `json:"required_permissions"`
	RequireMode         RequireMode       `json:"require_mode"`
}

// WildcardSemantics is the static, self-describing rule set a sidecar
// implements to reproduce permissions.Matches. It is constant (the match
// rules don't vary per client), embedded so the bundle is self-contained:
// an enforcer needs nothing but the bundle to know how a wanted permission
// is satisfied by a granted set.
type WildcardSemantics struct {
	// AllToken grants every permission ("*").
	AllToken string `json:"all_token"`
	// DomainSuffix, appended to a domain ("user:*"), grants every
	// "<domain>:<action>" under that domain.
	DomainSuffix string `json:"domain_suffix"`
	// Separator splits a "domain:action" code.
	Separator string `json:"separator"`
	// Rules is a human-readable description of the match order, mirroring
	// the doc comment on permissions.Matches.
	Rules []string `json:"rules"`
}

// StaticWildcardSemantics returns the constant match rules that mirror
// permissions.Matches. Kept in lockstep with matcher.go: a granted code
// satisfies a wanted code when it is "*", an exact match, or "<domain>:*"
// where the wanted code is "<domain>:<anything>".
func StaticWildcardSemantics() WildcardSemantics {
	return WildcardSemantics{
		AllToken:     WildcardAll,
		DomainSuffix: WildcardSuffix,
		Separator:    ":",
		Rules: []string{
			"exact: a granted code equal to the wanted code grants it",
			"domain: a granted '<domain>:*' grants any wanted '<domain>:<action>'",
			"all: a granted '*' grants any wanted code",
		},
	}
}

// BuildPolicyBundle reads every role defined under clientID from prov and
// renders the portable bundle. Roles are sorted by Code and each role's
// Permissions are copied (defensively, so a later store mutation can't
// alias into the returned bundle) and sorted, so the canonical form is
// STABLE: the same role set always yields the same CanonicalBytes (hence
// the same ETag) regardless of the provider's map-iteration order or when
// the export ran.
func BuildPolicyBundle(ctx context.Context, prov Provider, clientID string) (*PolicyBundle, error) {
	roles, err := prov.ListAllRoles(ctx, clientID)
	if err != nil {
		return nil, err
	}
	out := make([]RoleBundle, 0, len(roles))
	for _, r := range roles {
		perms := append([]string(nil), r.Permissions...)
		sort.Strings(perms)
		out = append(out, RoleBundle{
			Code:        r.Code,
			Name:        r.Name,
			Description: r.Description,
			Permissions: perms,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	resources, err := buildResourceBundles(ctx, prov, clientID)
	if err != nil {
		return nil, err
	}
	ssod, dsod, err := buildConflictSets(ctx, prov, clientID)
	if err != nil {
		return nil, err
	}
	return &PolicyBundle{
		Version:           PolicyBundleVersion,
		GeneratedAt:       time.Now().UTC(),
		ClientID:          clientID,
		Roles:             out,
		Resources:         resources,
		SSoDConflictSets:  ssod,
		DSoDConflictSets:  dsod,
		WildcardSemantics: StaticWildcardSemantics(),
	}, nil
}

func buildResourceBundles(ctx context.Context, prov Provider, clientID string) ([]ResourceBundle, error) {
	rp, ok := prov.(ResourceProvider)
	if !ok {
		return []ResourceBundle{}, nil
	}
	var (
		resources []*Resource
		err       error
	)
	if all, ok := rp.(ResourceCatalogLister); ok {
		resources, err = all.ListAllResources(ctx, clientID)
	} else {
		resources, err = rp.ListResources(ctx, "", clientID)
	}
	if err != nil {
		return nil, err
	}
	out := make([]ResourceBundle, 0, len(resources))
	for _, r := range resources {
		if r == nil {
			continue
		}
		perms := append([]string(nil), r.RequiredPermissions...)
		sort.Strings(perms)
		out = append(out, ResourceBundle{
			ID: r.ID, TenantID: r.TenantID, ClientID: r.ClientID,
			Type: r.Type, Name: r.Name, RequiresAuth: r.RequiresAuth,
			Description: r.Description, Attributes: cloneStringMap(r.Attributes),
			RequiredPermissions: perms, RequireMode: r.EffectiveRequireMode(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return resourceBundleKey(out[i]) < resourceBundleKey(out[j])
	})
	return out, nil
}

func buildConflictSets(ctx context.Context, prov Provider, clientID string) ([][]string, [][]string, error) {
	var ssod, dsod [][]string
	if p, ok := prov.(SoDProvider); ok {
		sets, err := p.ConflictSets(ctx, clientID)
		if err != nil {
			return nil, nil, err
		}
		ssod = normalizeConflictSets(sets)
	}
	if p, ok := prov.(SessionRoleActivator); ok {
		sets, err := p.ActivationConflictSets(ctx, clientID)
		if err != nil {
			return nil, nil, err
		}
		dsod = normalizeConflictSets(sets)
	}
	if ssod == nil {
		ssod = [][]string{}
	}
	if dsod == nil {
		dsod = [][]string{}
	}
	return ssod, dsod, nil
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func resourceBundleKey(r ResourceBundle) string {
	return strings.Join([]string{r.TenantID, r.ClientID, string(r.Type), r.Name, r.ID}, "\x00")
}

func normalizeConflictSets(in [][]string) [][]string {
	out := make([][]string, 0, len(in))
	for _, set := range in {
		codes := append([]string(nil), set...)
		sort.Strings(codes)
		out = append(out, codes)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.Join(out[i], "\x00") < strings.Join(out[j], "\x00")
	})
	return out
}

// CanonicalBytes returns the deterministic, ETag-hashable representation of
// the bundle's CONTENT: version + client + sorted roles + permissions +
// the static semantics, but NOT GeneratedAt (which changes every render
// and would otherwise defeat caching). The format is a hand-rolled,
// dependency-free, length-prefixed encoding — order-stable because
// BuildPolicyBundle already sorts roles and permissions, so identical role
// sets always produce identical bytes.
//
// Hashing this (rather than the JSON body, which embeds GeneratedAt) is
// what keeps the bundle's ETag stable across regenerations with unchanged
// roles.
func (b *PolicyBundle) CanonicalBytes() []byte {
	w := canonicalWriter{}
	w.field("v")
	w.field(itoa(b.Version))
	w.field("client")
	w.field(b.ClientID)
	w.field("sem")
	w.field(b.WildcardSemantics.AllToken)
	w.field(b.WildcardSemantics.DomainSuffix)
	w.field(b.WildcardSemantics.Separator)
	w.field(itoa(len(b.WildcardSemantics.Rules)))
	for _, rule := range b.WildcardSemantics.Rules {
		w.field(rule)
	}
	w.field("roles")
	w.field(itoa(len(b.Roles)))
	for _, r := range b.Roles {
		w.field("role")
		w.field(r.Code)
		w.field(r.Name)
		w.field(r.Description)
		w.field(itoa(len(r.Permissions)))
		for _, p := range r.Permissions {
			w.field(p)
		}
	}
	w.field("resources")
	w.field(itoa(len(b.Resources)))
	for _, r := range b.Resources {
		w.field("resource")
		w.field(r.ID)
		w.field(r.TenantID)
		w.field(r.ClientID)
		w.field(string(r.Type))
		w.field(r.Name)
		w.field(itoa(boolInt(r.RequiresAuth)))
		w.field(r.Description)
		w.field(string(r.RequireMode))
		w.strings(r.RequiredPermissions)
		w.stringMap(r.Attributes)
	}
	w.conflictSets("ssod", b.SSoDConflictSets)
	w.conflictSets("dsod", b.DSoDConflictSets)
	return w.buf
}

type canonicalWriter struct{ buf []byte }

func (w *canonicalWriter) field(s string) {
	var n [8]byte
	for i := range n {
		n[i] = byte(len(s) >> (8 * i))
	}
	w.buf = append(w.buf, n[:]...)
	w.buf = append(w.buf, s...)
}

func (w *canonicalWriter) strings(values []string) {
	w.field(itoa(len(values)))
	for _, value := range values {
		w.field(value)
	}
}

func (w *canonicalWriter) stringMap(values map[string]string) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	w.field(itoa(len(keys)))
	for _, key := range keys {
		w.field(key)
		w.field(values[key])
	}
}

func (w *canonicalWriter) conflictSets(label string, sets [][]string) {
	w.field(label)
	w.field(itoa(len(sets)))
	for _, set := range sets {
		w.strings(set)
	}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// itoa is a tiny non-negative int formatter, kept local to avoid pulling
// strconv into the canonical encoder's hot path.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
