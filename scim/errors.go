package scim

import "strconv"

// ErrorResponse is the SCIM error envelope (RFC 7644 §3.12). Status is
// the HTTP status repeated as a STRING per the spec ("404", not 404).
// ScimType refines a 4xx with a machine code from Table 9; Detail is the
// human-readable explanation.
type ErrorResponse struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

// newError builds a SCIM error body for an HTTP status. scimType may be
// "" for statuses (401/404/500) where RFC 7644 Table 9 defines no
// refinement code.
func newError(httpStatus int, scimType, detail string) ErrorResponse {
	return ErrorResponse{
		Schemas:  []string{SchemaError},
		Status:   strconv.Itoa(httpStatus),
		ScimType: scimType,
		Detail:   detail,
	}
}
