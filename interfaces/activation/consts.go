package activationhttp

const (
	PathPrepare = "/api/v1/activation/prepare"
	PathClaim   = "/api/v1/me/activation/claim"
	PathContext = "/api/v1/me/account-context"

	HeaderCacheControl = "Cache-Control"
	HeaderPragma       = "Pragma"

	ErrorActivationInvalid     = "activation_invalid"
	ErrorActivationNotFound    = "activation_not_found"
	ErrorActivationUnavailable = "activation_unavailable"
)
