package cors

// CORS-related HTTP header names. Per-package rather than shared
// because the cors package cannot import sso/consts.go (would cycle:
// sso → cors via WithCORS).
const (
	HeaderOrigin                     = "Origin"
	HeaderVary                       = "Vary"
	HeaderAccessControlAllowOrigin   = "Access-Control-Allow-Origin"
	HeaderAccessControlAllowMethods  = "Access-Control-Allow-Methods"
	HeaderAccessControlAllowHeaders  = "Access-Control-Allow-Headers"
	HeaderAccessControlAllowCreds    = "Access-Control-Allow-Credentials"
	HeaderAccessControlExposeHeaders = "Access-Control-Expose-Headers"
	HeaderAccessControlMaxAge        = "Access-Control-Max-Age"
	HeaderAccessControlRequestMethod = "Access-Control-Request-Method"
)

// Sentinel string values.
const (
	OriginWildcard = "*"
	TrueLiteral    = "true"
)

// Default header lists applied when Policy.AllowedMethods /
// AllowedHeaders are empty. Exposed so operators wiring a Policy can
// reference the same defaults instead of hard-coding their own.
var (
	DefaultAllowedMethods = []string{
		"GET", "POST", "PUT", "DELETE", "OPTIONS",
	}
	DefaultAllowedHeaders = []string{
		"Authorization", "Content-Type",
	}
)
