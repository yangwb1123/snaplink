package defaultimpl

// The opaque/simple token issuers (the HMAC JWTIssuer, the SessionTokenIssuer)
// and the HashLoginEntry credential-hash helper live in the defaulttoken leaf,
// and JWE response encryption/decryption (ECDH-ES, RSA-OAEP, and the
// multi/fan-out aggregators) lives in the defaultjwe leaf, so this directory
// stays within the per-directory file-count budget. Both leaves depend on
// shared/core directly (not the interfaces/sso facade), removing a latent
// upward import. These aliases preserve the historical defaultimpl.* import
// surface unchanged for every consumer; type aliases keep interface/struct
// identity intact.

import (
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/defaultjwe"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/defaulttoken"
)

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

type (
	ECDHJWEDecrypter          = defaultjwe.ECDHJWEDecrypter
	ECDHJWEResponseEncrypter  = defaultjwe.ECDHJWEResponseEncrypter
	RSAJWEDecrypter           = defaultjwe.RSAJWEDecrypter
	RSAJWEResponseEncrypter   = defaultjwe.RSAJWEResponseEncrypter
	MultiJWEDecrypter         = defaultjwe.MultiJWEDecrypter
	MultiJWEResponseEncrypter = defaultjwe.MultiJWEResponseEncrypter
)

var (
	NewECDHJWEDecrypter          = defaultjwe.NewECDHJWEDecrypter
	NewECDHJWEResponseEncrypter  = defaultjwe.NewECDHJWEResponseEncrypter
	NewRSAJWEDecrypter           = defaultjwe.NewRSAJWEDecrypter
	NewRSAJWEResponseEncrypter   = defaultjwe.NewRSAJWEResponseEncrypter
	NewMultiJWEDecrypter         = defaultjwe.NewMultiJWEDecrypter
	NewMultiJWEResponseEncrypter = defaultjwe.NewMultiJWEResponseEncrypter
)
