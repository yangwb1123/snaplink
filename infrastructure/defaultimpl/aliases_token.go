package defaultimpl

// The opaque/simple token issuers (the HMAC JWTIssuer, the SessionTokenIssuer)
// and the HashLoginEntry credential-hash helper live in the defaulttoken leaf so
// this directory stays within the per-directory file-count budget. defaulttoken
// depends on shared/core directly (not the interfaces/sso facade), removing a
// latent upward import. These aliases preserve the historical defaultimpl.*
// import surface unchanged.

import "github.com/snaplink/sso/infrastructure/defaultimpl/defaulttoken"

type (
	JWTIssuer           = defaulttoken.JWTIssuer
	JWTIssuerOption     = defaulttoken.JWTIssuerOption
	SessionIssuerOption = defaulttoken.SessionIssuerOption
	SessionTokenIssuer  = defaulttoken.SessionTokenIssuer
)

var (
	HashLoginEntry        = defaulttoken.HashLoginEntry
	NewJWTIssuer          = defaulttoken.NewJWTIssuer
	NewSessionTokenIssuer = defaulttoken.NewSessionTokenIssuer
	WithJWTIssuer         = defaulttoken.WithJWTIssuer
	WithJWTSecret         = defaulttoken.WithJWTSecret
	WithJWTTokenTTL       = defaulttoken.WithJWTTokenTTL
	WithSessionTokenTTL   = defaulttoken.WithSessionTokenTTL
)
