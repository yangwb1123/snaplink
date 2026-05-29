package scim

// SCIM 2.0 wire constants (RFC 7643 schema URNs / RFC 7644 protocol).
// Centralized here so no literal URN, schema id, or path leaks into the
// handler or mapping code (repo convention: no literal leaks).

// Schema URNs (RFC 7643 §10 + RFC 7644 §3.12 message schemas).
const (
	// SchemaUser is the core User resource schema URN (RFC 7643 §4.1).
	SchemaUser = "urn:ietf:params:scim:schemas:core:2.0:User"
	// SchemaListResponse wraps any multi-valued GET (RFC 7644 §3.4.2).
	SchemaListResponse = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	// SchemaError is the error envelope schema URN (RFC 7644 §3.12).
	SchemaError = "urn:ietf:params:scim:api:messages:2.0:Error"
	// SchemaServiceProviderConfig advertises supported features
	// (RFC 7643 §5).
	SchemaServiceProviderConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	// SchemaSchema is the schema-of-schemas URN used by GET /Schemas
	// (RFC 7643 §7).
	SchemaSchema = "urn:ietf:params:scim:schemas:core:2.0:Schema"
)

// resourceTypeUser is the "meta.resourceType" value stamped on every
// User resource (RFC 7643 §3.1).
const resourceTypeUser = "User"

// contentTypeSCIM is the media type for SCIM payloads (RFC 7644 §3.1).
// Responses set it; requests are accepted regardless of Content-Type so
// off-the-shelf provisioning clients that send application/json work.
const contentTypeSCIM = "application/scim+json"

// Route path suffixes. The Handler is mountable under any base prefix;
// these are the SCIM-relative paths it dispatches on. Operators mount it
// under e.g. /api/v1/scim/v2 (see cmd wiring) so admin auth applies.
const (
	pathUsers                 = "/Users"
	pathServiceProviderConfig = "/ServiceProviderConfig"
	pathSchemas               = "/Schemas"
)

// SCIM error "scimType" detail codes (RFC 7644 §3.12, Table 9). These
// refine a 4xx so a provisioning client can react programmatically.
const (
	// scimTypeInvalidValue: a required value was missing or malformed.
	scimTypeInvalidValue = "invalidValue"
	// scimTypeInvalidSyntax: the request body was not valid SCIM JSON.
	scimTypeInvalidSyntax = "invalidSyntax"
	// scimTypeUniqueness: a uniqueness constraint was violated (the id
	// or userName already exists). Pairs with HTTP 409.
	scimTypeUniqueness = "uniqueness"
	// scimTypeMutability: an immutable/read-only attribute was altered
	// (e.g. PUT tried to change id). Pairs with HTTP 400.
	scimTypeMutability = "mutability"
)

// core.User.Attributes keys backing SCIM fields that core.User has no
// dedicated column for. Namespaced under "scim:" so they never collide
// with the OIDC claim attributes (email/name/address/...) the login
// handler reads, and so a SCIM-provisioned user round-trips losslessly
// without enriching the core.User model. WHY namespaced: core.User is
// intentionally minimal (no userName/active fields); persisting SCIM-only
// attributes here keeps the integration additive and reversible.
const (
	attrUserName      = "scim:userName"
	attrActive        = "scim:active"
	attrNameGiven     = "scim:name.givenName"
	attrNameFamily    = "scim:name.familyName"
	attrNameMiddle    = "scim:name.middleName"
	attrNameFormatted = "scim:name.formatted"
	attrNamePrefix    = "scim:name.honorificPrefix"
	attrNameSuffix    = "scim:name.honorificSuffix"
	// attrEmailsExtra holds JSON-encoded non-primary emails so a
	// multi-valued emails array survives the round-trip through a
	// core.User that has a single Email field.
	attrEmailsExtra = "scim:emails.extra"
)

// Active-flag string values stored in attrActive (core.User.Attributes
// is map[string]string, so the bool is serialized).
const (
	activeTrue  = "true"
	activeFalse = "false"
)
