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
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystorecredential"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystoreidentity"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystoreoauth"
)

// --- memorystoreoauth ---
type (
	MemoryAuthCodeStore           = memorystoreoauth.MemoryAuthCodeStore
	MemoryCIBAStore               = memorystoreoauth.MemoryCIBAStore
	MemoryCIBAPushDeadLetterStore = memorystoreoauth.MemoryCIBAPushDeadLetterStore
	MemoryDeviceCodeStore         = memorystoreoauth.MemoryDeviceCodeStore
	MemoryDeviceSecretStore       = memorystoreoauth.MemoryDeviceSecretStore
	MemoryPARStore                = memorystoreoauth.MemoryPARStore
	MemoryRefreshTokenStore       = memorystoreoauth.MemoryRefreshTokenStore
)

var (
	GenerateAuthCode                 = memorystoreoauth.GenerateAuthCode
	GenerateCIBAAuthReqID            = memorystoreoauth.GenerateCIBAAuthReqID
	GenerateDeviceCode               = memorystoreoauth.GenerateDeviceCode
	GeneratePARToken                 = memorystoreoauth.GeneratePARToken
	GenerateRefreshToken             = memorystoreoauth.GenerateRefreshToken
	GenerateUserCode                 = memorystoreoauth.GenerateUserCode
	NewMemoryAuthCodeStore           = memorystoreoauth.NewMemoryAuthCodeStore
	NewMemoryCIBAStore               = memorystoreoauth.NewMemoryCIBAStore
	NewMemoryCIBAPushDeadLetterStore = memorystoreoauth.NewMemoryCIBAPushDeadLetterStore
	NewMemoryDeviceCodeStore         = memorystoreoauth.NewMemoryDeviceCodeStore
	NewMemoryDeviceSecretStore       = memorystoreoauth.NewMemoryDeviceSecretStore
	NewMemoryPARStore                = memorystoreoauth.NewMemoryPARStore
	NewMemoryRefreshTokenStore       = memorystoreoauth.NewMemoryRefreshTokenStore
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
	NewMemoryClientStore        = memorystoreidentity.NewMemoryClientStore
	NewMemoryConsentStore       = memorystoreidentity.NewMemoryConsentStore
	NewMemoryInvitationStore    = memorystoreidentity.NewMemoryInvitationStore
	NewMemorySessionManager     = memorystoreidentity.NewMemorySessionManager
	NewMemorySubjectClientIndex = memorystoreidentity.NewMemorySubjectClientIndex
	NewMemoryTenantUserStore    = memorystoreidentity.NewMemoryTenantUserStore
	NewMemoryUserProvider       = memorystoreidentity.NewMemoryUserProvider
)

// BcryptCost returns the bcrypt work factor memorystoreidentity's client
// store uses to hash secrets. A plain `var BcryptCost = memorystoreidentity.BcryptCost`
// alias (as used above for every other re-export in this file) copies the
// int VALUE once at package-init time — it does not share storage with
// memorystoreidentity.BcryptCost, so a later `defaultimpl.BcryptCost = x`
// would silently never reach the variable hashClientSecret actually reads.
// These forwarding functions read/write memorystoreidentity's live variable
// instead.
func BcryptCost() int { return memorystoreidentity.BcryptCost }

// SetBcryptCost overrides the bcrypt work factor (test-only knob — lower
// cost trades security for speed; never use in production). See
// [BcryptCost]'s doc for why this can't be a plain exported var.
func SetBcryptCost(cost int) { memorystoreidentity.BcryptCost = cost }

// --- memorystorecredential ---
type (
	MemoryCredentialStatusStore   = memorystorecredential.MemoryCredentialStatusStore
	MemoryDependentPartyNotifier  = memorystorecredential.MemoryDependentPartyNotifier
	MemoryEmailChangeStore        = memorystorecredential.MemoryEmailChangeStore
	MemoryEmailVerificationStore  = memorystorecredential.MemoryEmailVerificationStore
	MemoryIPFailureCounter        = memorystorecredential.MemoryIPFailureCounter
	MemoryJTIReplayStore          = memorystorecredential.MemoryJTIReplayStore
	MemoryPasswordCredentialStore = memorystorecredential.MemoryPasswordCredentialStore
	MemoryPasswordResetStore      = memorystorecredential.MemoryPasswordResetStore
	MemoryRecentLoginStore        = memorystorecredential.MemoryRecentLoginStore
	MemoryRecentLoginStoreOption  = memorystorecredential.MemoryRecentLoginStoreOption
	MemoryRecoveryCodeStore       = memorystorecredential.MemoryRecoveryCodeStore
	MemoryTrustedDeviceStore      = memorystorecredential.MemoryTrustedDeviceStore
)

var (
	NewMemoryCredentialStatusStore   = memorystorecredential.NewMemoryCredentialStatusStore
	NewMemoryDependentPartyNotifier  = memorystorecredential.NewMemoryDependentPartyNotifier
	NewMemoryEmailChangeStore        = memorystorecredential.NewMemoryEmailChangeStore
	NewMemoryEmailVerificationStore  = memorystorecredential.NewMemoryEmailVerificationStore
	NewMemoryIPFailureCounter        = memorystorecredential.NewMemoryIPFailureCounter
	NewMemoryJTIReplayStore          = memorystorecredential.NewMemoryJTIReplayStore
	NewMemoryPasswordCredentialStore = memorystorecredential.NewMemoryPasswordCredentialStore
	NewMemoryPasswordResetStore      = memorystorecredential.NewMemoryPasswordResetStore
	NewMemoryRecentLoginStore        = memorystorecredential.NewMemoryRecentLoginStore
	NewMemoryRecoveryCodeStore       = memorystorecredential.NewMemoryRecoveryCodeStore
	NewMemoryTrustedDeviceStore      = memorystorecredential.NewMemoryTrustedDeviceStore
	WithRecentLoginPerSubjectCap     = memorystorecredential.WithRecentLoginPerSubjectCap
)
