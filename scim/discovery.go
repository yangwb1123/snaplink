package scim

// Discovery documents (RFC 7643 §5 ServiceProviderConfig + §7 Schemas).
// These advertise EXACTLY what this slice implements — PATCH (RFC 7644
// §3.5.2) and filtering (RFC 7644 §3.4.2.2), but no bulk, no sort, no
// ETag, no change-password — so a provisioning client negotiates correctly
// instead of attempting unsupported operations. New capabilities flip the
// relevant "supported" flag.

// supportedFeature is the {supported:bool} shape ServiceProviderConfig
// uses for several capability blocks (RFC 7643 §5).
type supportedFeature struct {
	Supported bool `json:"supported"`
}

// bulkFeature advertises Bulk support + its size limits (RFC 7644 §3.7).
type bulkFeature struct {
	Supported      bool `json:"supported"`
	MaxOperations  int  `json:"maxOperations"`
	MaxPayloadSize int  `json:"maxPayloadSize"`
}

// filterFeature adds the filter result cap.
type filterFeature struct {
	Supported  bool `json:"supported"`
	MaxResults int  `json:"maxResults"`
}

// authScheme describes one supported auth method (RFC 7643 §5).
type authScheme struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Primary     bool   `json:"primary,omitempty"`
}

// ServiceProviderConfig is the GET /ServiceProviderConfig body.
type ServiceProviderConfig struct {
	Schemas               []string         `json:"schemas"`
	DocumentationURI      string           `json:"documentationUri,omitempty"`
	Patch                 supportedFeature `json:"patch"`
	Bulk                  bulkFeature      `json:"bulk"`
	Filter                filterFeature    `json:"filter"`
	ChangePassword        supportedFeature `json:"changePassword"`
	Sort                  supportedFeature `json:"sort"`
	ETag                  supportedFeature `json:"etag"`
	AuthenticationSchemes []authScheme     `json:"authenticationSchemes"`
	Meta                  *Meta            `json:"meta,omitempty"`
}

// serviceProviderConfig returns the static capability advertisement for
// this slice. Bearer (OAuth) is the only auth scheme because the Handler
// is mounted behind the server's admin Bearer middleware.
func serviceProviderConfig() ServiceProviderConfig {
	return ServiceProviderConfig{
		Schemas: []string{SchemaServiceProviderConfig},
		// PATCH is implemented for Users + Groups (RFC 7644 §3.5.2): the
		// add/replace/remove op model, including the active=false
		// deprovision path Azure AD / Okta drive.
		Patch: supportedFeature{Supported: true},
		// Bulk is implemented for Users + Groups (RFC 7644 §3.7): POST /Bulk
		// replays each operation through the per-resource handlers and resolves
		// bulkId cross-references. Limits below are enforced by the handler.
		Bulk: bulkFeature{Supported: true, MaxOperations: bulkMaxOperations, MaxPayloadSize: bulkMaxPayloadSize},
		// Filtering is implemented for GET /Users + /Groups (RFC 7644
		// §3.4.2.2): the comparison/logical/grouping subset connectors use
		// to reconcile a single resource. maxResults bounds a filtered page
		// (a filtered list still pages through paginationParams).
		Filter:         filterFeature{Supported: true, MaxResults: filterMaxResults},
		ChangePassword: supportedFeature{Supported: false},
		Sort:           supportedFeature{Supported: false},
		ETag:           supportedFeature{Supported: false},
		AuthenticationSchemes: []authScheme{{
			Type:        "oauthbearertoken",
			Name:        "OAuth Bearer Token",
			Description: "Authentication via the SSO admin OAuth 2.0 bearer token.",
			Primary:     true,
		}},
		Meta: &Meta{ResourceType: "ServiceProviderConfig"},
	}
}

// schemaAttribute is one entry in a schema's "attributes" array
// (RFC 7643 §7). Only the fields a connector inspects are modeled.
type schemaAttribute struct {
	Name          string            `json:"name"`
	Type          string            `json:"type"`
	MultiValued   bool              `json:"multiValued"`
	Required      bool              `json:"required"`
	CaseExact     bool              `json:"caseExact"`
	Mutability    string            `json:"mutability"`
	Returned      string            `json:"returned"`
	Uniqueness    string            `json:"uniqueness,omitempty"`
	SubAttributes []schemaAttribute `json:"subAttributes,omitempty"`
}

// SchemaResource describes one resource schema (RFC 7643 §7), as returned
// by GET /Schemas.
type SchemaResource struct {
	Schemas     []string          `json:"schemas"`
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Attributes  []schemaAttribute `json:"attributes"`
	Meta        *Meta             `json:"meta,omitempty"`
}

// userSchema returns the description of the subset of the core User
// schema this slice implements (RFC 7643 §4.1) — exactly the attributes
// the Handler reads and writes, so a connector that introspects /Schemas
// won't push attributes that get silently dropped.
func userSchema() SchemaResource {
	return SchemaResource{
		Schemas:     []string{SchemaSchema},
		ID:          SchemaUser,
		Name:        resourceTypeUser,
		Description: "User Account",
		Attributes: []schemaAttribute{
			{
				Name: "userName", Type: "string", Required: true,
				Mutability: "readWrite", Returned: "default", Uniqueness: "server",
			},
			{
				Name: "name", Type: "complex", Mutability: "readWrite", Returned: "default",
				SubAttributes: []schemaAttribute{
					{Name: "formatted", Type: "string", Mutability: "readWrite", Returned: "default"},
					{Name: "familyName", Type: "string", Mutability: "readWrite", Returned: "default"},
					{Name: "givenName", Type: "string", Mutability: "readWrite", Returned: "default"},
					{Name: "middleName", Type: "string", Mutability: "readWrite", Returned: "default"},
					{Name: "honorificPrefix", Type: "string", Mutability: "readWrite", Returned: "default"},
					{Name: "honorificSuffix", Type: "string", Mutability: "readWrite", Returned: "default"},
				},
			},
			{Name: "displayName", Type: "string", Mutability: "readWrite", Returned: "default"},
			{
				Name: "emails", Type: "complex", MultiValued: true,
				Mutability: "readWrite", Returned: "default",
				SubAttributes: []schemaAttribute{
					{Name: "value", Type: "string", Mutability: "readWrite", Returned: "default"},
					{Name: "type", Type: "string", Mutability: "readWrite", Returned: "default"},
					{Name: "primary", Type: "boolean", Mutability: "readWrite", Returned: "default"},
				},
			},
			{Name: "active", Type: "boolean", Mutability: "readWrite", Returned: "default"},
			{Name: "externalId", Type: "string", Mutability: "readWrite", Returned: "default", CaseExact: true},
		},
		Meta: &Meta{ResourceType: "Schema"},
	}
}

// groupSchema returns the description of the subset of the core Group
// schema this slice implements (RFC 7643 §4.2) — displayName plus the
// multi-valued members attribute. Advertised by GET /Schemas only when
// WithGroups is wired, so a connector won't push group attributes a
// deployment without a permissions provider would drop.
func groupSchema() SchemaResource {
	return SchemaResource{
		Schemas:     []string{SchemaSchema},
		ID:          SchemaGroup,
		Name:        resourceTypeGroup,
		Description: "Group",
		Attributes: []schemaAttribute{
			{
				Name: "displayName", Type: "string", Required: true,
				Mutability: "readWrite", Returned: "default",
			},
			{
				Name: "members", Type: "complex", MultiValued: true,
				Mutability: "readWrite", Returned: "default",
				SubAttributes: []schemaAttribute{
					// value is immutable per RFC 7643 §4.2 (a member ref is
					// added/removed, never mutated in place).
					{Name: "value", Type: "string", Mutability: "immutable", Returned: "default"},
					{Name: "$ref", Type: "reference", Mutability: "immutable", Returned: "default"},
					{Name: "type", Type: "string", Mutability: "immutable", Returned: "default"},
				},
			},
		},
		Meta: &Meta{ResourceType: "Schema"},
	}
}
