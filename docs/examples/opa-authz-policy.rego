# Reference OPA policy for decentralized SSO authorization.
#
# This is a DOC EXAMPLE, not production code: it shows how a service-mesh
# sidecar enforces authorization LOCALLY from two inputs, with NO
# per-request RPC back to the SSO server:
#
#   1. data.bundle  — the role-DEFINITION bundle pulled from
#                      GET /api/v1/admin/authz/policy-bundle?client_id=<id>
#                      (code -> permissions[] + wildcard_semantics).
#   2. input.roles  — the caller's role CODES, taken from the access
#                      token. The SSO server embeds them in the login
#                      response when WithEmbedPermissionsInLogin is set, so
#                      the sidecar reads them from the validated token; the
#                      assignment half of the model never crosses the wire.
#   3. input.want   — the permission the request requires
#                      (e.g. "order:create").
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
granted contains code if {
	some role_code in input.roles
	some role in data.bundle.roles
	role.code == role_code
	some code in role.permissions
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

# Final decision. Default deny: an unknown role, an empty want, or a
# permission no held role grants all evaluate to false.
default allow := false

allow if satisfies
