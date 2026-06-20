package defaultimpl

// JWE response encryption/decryption (ECDH-ES, RSA-OAEP, and the multi/fan-out
// aggregators) lives in the defaultjwe leaf so this directory stays within the
// per-directory file-count budget. defaultjwe depends on shared/core directly
// (not the interfaces/sso facade), which also removes a latent upward import.
// These aliases preserve the historical defaultimpl.* import surface unchanged
// for every consumer; type aliases keep interface/struct identity intact.

import "github.com/snaplink/sso/infrastructure/defaultimpl/defaultjwe"

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
