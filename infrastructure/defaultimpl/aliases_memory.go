package defaultimpl

// The in-memory SPI store implementations live in three cohesive leaf
// sub-packages so this directory stays within the per-directory file-count
// budget: memorystoreoauth (OAuth grant/token stores), memorystoreidentity
// (user/client/session/consent/tenant stores) and memorystorecredential
// (password/anti-abuse/replay stores). Each leaf depends on shared/core
// directly instead of the interfaces/sso facade, removing a latent upward
// import. These aliases preserve the historical defaultimpl.* import surface
// unchanged; type aliases keep interface identity intact.

import (
	"github.com/snaplink/sso/infrastructure/defaultimpl/memorystorecredential"
	"github.com/snaplink/sso/infrastructure/defaultimpl/memorystoreidentity"
	"github.com/snaplink/sso/infrastructure/defaultimpl/memorystoreoauth"
)

// --- memorystoreoauth ---
type (
	MemoryAuthCodeStore     = memorystoreoauth.MemoryAuthCodeStore
	MemoryCIBAStore         = memorystoreoauth.MemoryCIBAStore
	MemoryDeviceCodeStore   = memorystoreoauth.MemoryDeviceCodeStore
	MemoryDeviceSecretStore = memorystoreoauth.MemoryDeviceSecretStore
	MemoryPARStore          = memorystoreoauth.MemoryPARStore
	MemoryRefreshTokenStore = memorystoreoauth.MemoryRefreshTokenStore
)

var (
	GenerateAuthCode           = memorystoreoauth.GenerateAuthCode
	GenerateCIBAAuthReqID      = memorystoreoauth.GenerateCIBAAuthReqID
	GenerateDeviceCode         = memorystoreoauth.GenerateDeviceCode
	GeneratePARToken           = memorystoreoauth.GeneratePARToken
	GenerateRefreshToken       = memorystoreoauth.GenerateRefreshToken
	GenerateUserCode           = memorystoreoauth.GenerateUserCode
	NewMemoryAuthCodeStore     = memorystoreoauth.NewMemoryAuthCodeStore
	NewMemoryCIBAStore         = memorystoreoauth.NewMemoryCIBAStore
	NewMemoryDeviceCodeStore   = memorystoreoauth.NewMemoryDeviceCodeStore
	NewMemoryDeviceSecretStore = memorystoreoauth.NewMemoryDeviceSecretStore
	NewMemoryPARStore          = memorystoreoauth.NewMemoryPARStore
	NewMemoryRefreshTokenStore = memorystoreoauth.NewMemoryRefreshTokenStore
)

// --- memorystoreidentity ---
type (
	MemoryClientStore        = memorystoreidentity.MemoryClientStore
	MemoryConsentStore       = memorystoreidentity.MemoryConsentStore
	MemoryInvitationStore    = memorystoreidentity.MemoryInvitationStore
	MemorySessionManager     = memorystoreidentity.MemorySessionManager
	MemorySubjectClientIndex = memorystoreidentity.MemorySubjectClientIndex
	MemoryTenantUserStore    = memorystoreidentity.MemoryTenantUserStore
	MemoryUserProvider       = memorystoreidentity.MemoryUserProvider
)

var (
	BcryptCost                  = memorystoreidentity.BcryptCost
	NewMemoryClientStore        = memorystoreidentity.NewMemoryClientStore
	NewMemoryConsentStore       = memorystoreidentity.NewMemoryConsentStore
	NewMemoryInvitationStore    = memorystoreidentity.NewMemoryInvitationStore
	NewMemorySessionManager     = memorystoreidentity.NewMemorySessionManager
	NewMemorySubjectClientIndex = memorystoreidentity.NewMemorySubjectClientIndex
	NewMemoryTenantUserStore    = memorystoreidentity.NewMemoryTenantUserStore
	NewMemoryUserProvider       = memorystoreidentity.NewMemoryUserProvider
)

// --- memorystorecredential ---
type (
	MemoryCredentialStatusStore   = memorystorecredential.MemoryCredentialStatusStore
	MemoryEmailChangeStore        = memorystorecredential.MemoryEmailChangeStore
	MemoryEmailVerificationStore  = memorystorecredential.MemoryEmailVerificationStore
	MemoryIPFailureCounter        = memorystorecredential.MemoryIPFailureCounter
	MemoryJTIReplayStore          = memorystorecredential.MemoryJTIReplayStore
	MemoryPasswordCredentialStore = memorystorecredential.MemoryPasswordCredentialStore
	MemoryPasswordResetStore      = memorystorecredential.MemoryPasswordResetStore
	MemoryRecentLoginStore        = memorystorecredential.MemoryRecentLoginStore
	MemoryRecentLoginStoreOption  = memorystorecredential.MemoryRecentLoginStoreOption
)

var (
	NewMemoryCredentialStatusStore   = memorystorecredential.NewMemoryCredentialStatusStore
	NewMemoryEmailChangeStore        = memorystorecredential.NewMemoryEmailChangeStore
	NewMemoryEmailVerificationStore  = memorystorecredential.NewMemoryEmailVerificationStore
	NewMemoryIPFailureCounter        = memorystorecredential.NewMemoryIPFailureCounter
	NewMemoryJTIReplayStore          = memorystorecredential.NewMemoryJTIReplayStore
	NewMemoryPasswordCredentialStore = memorystorecredential.NewMemoryPasswordCredentialStore
	NewMemoryPasswordResetStore      = memorystorecredential.NewMemoryPasswordResetStore
	NewMemoryRecentLoginStore        = memorystorecredential.NewMemoryRecentLoginStore
	WithRecentLoginPerSubjectCap     = memorystorecredential.WithRecentLoginPerSubjectCap
)
