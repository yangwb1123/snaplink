package permissions

import (
	"context"
	"sort"
	"time"
)

// PolicyBundleVersion is the schema version of the exported bundle. A
// sidecar branches on it so a future incompatible shape can ship without
// silently breaking existing enforcers. Bump only on a breaking change.
const PolicyBundleVersion = 1

// PolicyBundle is the portable, role-DEFINITION export a service-mesh
// sidecar (OPA/Cedar/custom) pulls to enforce authorization LOCALLY,
// without a per-request Authorizer RPC back to the SSO server.
//
// It deliberately carries ONLY role definitions (code -> permissions[] +
// the wildcard match rules), NOT the per-subject role assignments: a
// sidecar already has the caller's roles from the token (the SSO server
// embeds them when WithEmbedPermissionsInLogin is set), so the assignment
// half of the model never needs to leave the server. Shipping assignments
// would bloat the bundle to O(users) and leak the whole directory; this
// stays O(roles) and contains no PII.
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
	return &PolicyBundle{
		Version:           PolicyBundleVersion,
		GeneratedAt:       time.Now().UTC(),
		ClientID:          clientID,
		Roles:             out,
		WildcardSemantics: StaticWildcardSemantics(),
	}, nil
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
	var buf []byte
	writeField := func(s string) {
		// Length-prefix every field so no value can be confused with a
		// delimiter (a permission code containing a separator byte can't
		// collide with the framing).
		var n [8]byte
		l := len(s)
		for i := 0; i < 8; i++ {
			n[i] = byte(l >> (8 * i))
		}
		buf = append(buf, n[:]...)
		buf = append(buf, s...)
	}
	writeField("v")
	writeField(itoa(b.Version))
	writeField("client")
	writeField(b.ClientID)
	writeField("sem")
	writeField(b.WildcardSemantics.AllToken)
	writeField(b.WildcardSemantics.DomainSuffix)
	writeField(b.WildcardSemantics.Separator)
	writeField("roles")
	writeField(itoa(len(b.Roles)))
	for _, r := range b.Roles {
		writeField("role")
		writeField(r.Code)
		writeField(r.Name)
		writeField(r.Description)
		writeField(itoa(len(r.Permissions)))
		for _, p := range r.Permissions {
			writeField(p)
		}
	}
	return buf
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
