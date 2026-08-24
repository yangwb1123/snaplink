# Reference OPA policy for decentralized SSO authorization.
#
# This is a DOC EXAMPLE, not production code: it shows how a service-mesh
# sidecar enforces authorization LOCALLY from two inputs, with NO
# per-request RPC back to the SSO server:
#
#   1. data.bundle  — the role-DEFINITION bundle pulled from
#                      GET /api/v1/admin/authz/policy-bundle?client_id=<id>
#                      (code -> permissions[] + wildcard_semantics).
#   2. input.roles or input.session_roles — the caller's role CODES, taken from the access
#                      token. The SSO server embeds them in the login
#                      response when WithEmbedPermissionsInLogin is set, so
#                      the sidecar reads them from the validated token; the
#                      assignment half of the model never crosses the wire.
#                      For a session-scoped decision these are ACTIVE roles.
#   3. input.want   — the permission the request requires
#                      (e.g. "order:create").
#   4. input.resource (optional) — {type, tenant_id, attributes} matching
#                      the request's resource-catalog lookup. A catalog miss
#                      follows the server's flat-permission fallback.
#
# The matcher below reproduces permissions.Matches EXACTLY:
#
#   exact:   a granted "user:read"  satisfies a wanted "user:read"
#   domain:  a granted "user:*"     satisfies any wanted "user:<action>"
#   all:     a granted "*"          satisfies any wanted permission
#
# Example load:
#   opa eval -d opa-authz-policy.rego \
#     -d <(curl -s -H 'Authorization: Bearer <admin>' \
#            '$SSO/api/v1/admin/authz/policy-bundle?client_id=web-app' \
#            | jq '{bundle: .}') \
#     -i request.json 'data.authz.allow'

package authz

import rego.v1

# The permission codes granted by the caller's held roles, flattened from
# the bundle's role definitions. A token role with no matching definition
# in the bundle contributes nothing (fail-closed).
caller_roles := object.get(input, "session_roles", object.get(input, "roles", []))

granted contains code if {
	some role_code in caller_roles
	some role in data.bundle.roles
	role.code == role_code
	some code in role.permissions
}

# A session role projection must be conflict-free. The server enforces this
# at activation time; this guard makes a sidecar fail closed on a stale or
# malformed token carrying mutually exclusive active roles.
conflict_sets := array.concat(data.bundle.ssod_conflict_sets, data.bundle.dsod_conflict_sets)

role_conflict if {
	input.session_id != ""
	some conflict_set in conflict_sets
	count({role_code | some role_code in caller_roles; role_code in conflict_set}) >= 2
}

# Wildcard tokens come from the bundle's self-describing semantics so the
# sidecar needs no hardcoded knowledge of the match rules — if the SSO
# server ever changed them, the bundle carries the new values.
all_token := data.bundle.wildcard_semantics.all_token

domain_suffix := data.bundle.wildcard_semantics.domain_suffix

separator := data.bundle.wildcard_semantics.separator

# all: a granted "*" satisfies anything.
satisfies if {
	all_token in granted
}

# exact: a granted code equal to the wanted code.
satisfies if {
	input.want in granted
}

# domain: a granted "<domain>:*" satisfies a wanted "<domain>:<action>".
satisfies if {
	some code in granted
	endswith(code, domain_suffix)
	domain := trim_suffix(code, domain_suffix)
	startswith(input.want, concat("", [domain, separator]))
}

permission_satisfied(want) if {
	all_token in granted
}

permission_satisfied(want) if {
	some code in granted
	permission_satisfied_code(code, want)
}

permission_satisfied_code(code, want) if code == want

permission_satisfied_code(code, want) if {
	endswith(code, domain_suffix)
	domain := trim_suffix(code, domain_suffix)
	startswith(want, concat("", [domain, separator]))
}

resource_matches contains resource if {
	some resource in data.bundle.resources
	resource.type == input.resource.type
	object.get(resource, "tenant_id", "") == object.get(input.resource, "tenant_id", "")
	object.get(resource, "client_id", "") == object.get(input.resource, "client_id", object.get(resource, "client_id", ""))
	resource_attributes_match(resource.type, resource.attributes, object.get(input.resource, "attributes", {}))
}

resource_attributes_match("http_api", expected, actual) if {
	lower(expected.method) == lower(actual.method)
	http_path_matches(expected.path, actual.path)
}

resource_attributes_match(_, expected, actual) if {
	count(expected) == count(actual)
	every key, value in expected {
		actual[key] == value
	}
}

http_path_matches(expected, actual) if expected == actual

http_path_matches(expected, actual) if {
	expected_segments := split(expected, "/")
	actual_segments := split(actual, "/")
	count(expected_segments) == count(actual_segments)
	every index, segment in expected_segments {
		http_path_segment_matches(segment, actual_segments[index])
	}
}

http_path_segment_matches(expected, actual) if startswith(expected, ":")

http_path_segment_matches(expected, actual) if expected == actual

resource_allowed if {
	not input.resource
	satisfies
}

resource_allowed if {
	input.resource
	count(resource_matches) == 0
	satisfies
}

resource_allowed if {
	some resource in resource_matches
	resource.requires_auth == false
}

resource_allowed if {
	some resource in resource_matches
	resource.requires_auth == true
	count(resource.required_permissions) == 0
}

resource_allowed if {
	some resource in resource_matches
	resource.requires_auth == true
	count(resource.required_permissions) > 0
	resource_permissions_allowed(resource)
}

resource_permissions_allowed(resource) if {
	resource.require_mode == "all"
	not resource_missing_permission(resource)
}

resource_permissions_allowed(resource) if {
	resource.require_mode != "all"
	some required in resource.required_permissions
	permission_satisfied(required)
}

resource_missing_permission(resource) if {
	some required in resource.required_permissions
	not permission_satisfied(required)
}

# Final decision. Default deny: an unknown role, an empty want, or a
# permission no held role grants all evaluate to false.
default allow := false

allow if {
	not role_conflict
	resource_allowed
}
