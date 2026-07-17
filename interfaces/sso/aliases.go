// Code generated. Backward-compat re-exports of core package symbols.
package sso

import (
	"github.com/snaplink/sso/domains/conditionalaccess"
	"github.com/snaplink/sso/domains/tenant"
	"github.com/snaplink/sso/interfaces/admin"
	"github.com/snaplink/sso/interfaces/middleware"
	"github.com/snaplink/sso/internal/handler"
	"github.com/snaplink/sso/platform/geo"
	"github.com/snaplink/sso/platform/lifecycle/degradation"
	"github.com/snaplink/sso/protocols/fapi"
	"github.com/snaplink/sso/shared/core"
)

// --- Disaster-recovery degraded-service re-exports (moved to
// platform/lifecycle/degradation) so callers configure WithDegradationManager
// without importing the platform package directly. ---
type (
	DegradationManager = degradation.Manager
	DegradationMode    = degradation.Mode
)

const (
	DegradationModeNormal      = degradation.ModeNormal
	DegradationModeReadOnly    = degradation.ModeReadOnly
	DegradationModeAuthOnly    = degradation.ModeAuthOnly
	DegradationModeLocalOnly   = degradation.ModeLocalOnly
	DegradationModeMaintenance = degradation.ModeMaintenance
)

var NewDegradationManager = degradation.NewManager

// FAPIMode re-exports fapi.Mode so callers configure WithFAPIProfile
// without importing the fapi package directly.
type FAPIMode = fapi.Mode

const (
	FAPIModeOff        = fapi.ModeOff
	FAPIModeInspection = fapi.ModeInspection
	FAPIModeEnforce    = fapi.ModeEnforce
)

// Zero-trust Conditional Access Policy (CAP) re-exports so SDK callers
// configure WithConditionalAccess and read EvaluateConditionalAccess results
// without importing the domains/conditionalaccess package directly.
type ConditionalAccessStore = conditionalaccess.Store
type ConditionalAccessPolicy = conditionalaccess.Policy
type ConditionalAccessConfig = conditionalaccess.Config
type AccessContext = conditionalaccess.AccessContext
type ConditionalAccessDecision = conditionalaccess.Decision

// Client-authentication method names per RFC 8705 §2 / RFC 7591 §2.
// These are the canonical values stored on [core.Client.TokenEndpointAuthMethod]
// and accepted by DCR validation (oauthvalidate/dcr_validate.go).
const (
	ClientAuthTLS           = "tls_client_auth"
	ClientAuthSelfSignedTLS = "self_signed_tls"
)

// --- General middleware re-exports (functions moved to middleware/) ---
var AuthMiddleware = middleware.Auth
var CORS = middleware.CORS
var LoggerMiddleware = middleware.Logger
var TracingMiddleware = middleware.Tracing
var RequestIDMiddleware = middleware.RequestID
var RecoverMiddleware = middleware.Recover

// --- BuildInfo re-export (moved to core/) ---
type BuildInfo = core.BuildInfo

var ReadBuildInfo = core.ReadBuildInfo

// --- Permission/netpolicy constant re-exports (moved to core/) ---
const KeyPermissions = core.KeyPermissions
const KeyRoles = core.KeyRoles
const KeyMenus = core.KeyMenus
const KeyClient = core.KeyClient
const ErrPermissionProviderNotConfigured = core.ErrPermissionProviderNotConfigured
const ErrPermissionLookupFailed = core.ErrPermissionLookupFailed

// --- Admin middleware re-exports (functions moved to admin/) ---
type AdminMiddleware = admin.Middleware
type AdminTokenValidator = admin.TokenValidator
type AdminAuthorizer = admin.Authorizer

const AdminScope = admin.Scope
const AdminScopeRead = admin.ScopeRead
const AdminScopeWrite = admin.ScopeWrite

var NewAdminMiddleware = admin.NewMiddleware
var AdminActorFromContext = admin.ActorFromContext

// --- Tenant middleware re-exports (functions moved to tenant/) ---
type ResolvedTenant = tenant.Resolved
type TenantMiddlewareOptions = tenant.MiddlewareOptions
type HostExtractor = tenant.HostExtractor

const TenantHandlerContextKey = tenant.HandlerContextKey
const DefaultTenantLookupTimeout = tenant.DefaultLookupTimeout

var TenantMiddleware = tenant.Middleware
var TenantFromHandlerContext = tenant.FromHandlerContext
var DefaultHostExtractor = tenant.DefaultHostExtractor

// --- Geo middleware re-exports (functions moved to geo/) ---
type GeoMiddlewareOptions = geo.MiddlewareOptions
type GeoIPExtractor = geo.IPExtractor

const GeoHandlerContextKey = geo.HandlerContextKey
const DefaultGeoLookupTimeout = geo.DefaultLookupTimeout

var GeoMiddleware = geo.Middleware
var GeoFromHandlerContext = geo.FromHandlerContext
var DefaultGeoIPExtractor = geo.DefaultIPExtractor

// --- Types ---
type ActorClaim = core.ActorClaim
type Authenticator = core.Authenticator
type LockoutKeyer = core.LockoutKeyer
type AuthRequest = core.AuthRequest
type AuthResult = core.AuthResult
type CredentialHealth = core.CredentialHealth
type CallbackState = core.CallbackState
type Client = core.Client
type ClientStore = core.ClientStore
type ClientStoreStats = core.ClientStoreStats
type Context = core.Context
type HandlerContext = core.HandlerContext
type HandlerFunc = core.HandlerFunc
type JWK = core.JWK
type JWKSProvider = core.JWKSProvider
type MiddlewareFunc = core.MiddlewareFunc
type Router = core.Router
type Session = core.Session
type SessionManager = core.SessionManager
type SessionMeta = core.SessionMeta
type SessionMetaCreator = core.SessionMetaCreator
type SessionTenantIndex = core.SessionTenantIndex
type SessionTenantLister = core.SessionTenantLister
type SessionTrustManager = core.SessionTrustManager
type TenantQuotaStore = core.TenantQuotaStore
type TenantQuota = core.TenantQuota
type TenantUserStore = core.TenantUserStore
type TenantMembership = core.TenantMembership
type TenantRole = core.TenantRole
type InvitationStore = core.InvitationStore
type Invitation = core.Invitation
type StdRoute = core.StdRoute
type StdRouter = core.StdRouter
type Subject = core.Subject
type TenantScopedClientStore = core.TenantScopedClientStore
type Token = core.Token
type TokenClaims = core.TokenClaims
type TokenFormatHinter = core.TokenFormatHinter
type TokenIssuer = core.TokenIssuer
type TokenLister = core.TokenLister
type ConsentGrant = core.ConsentGrant
type ConsentStore = core.ConsentStore
type AdminTokenStore = core.AdminTokenStore
type AdminSession = core.AdminSession
type BreakGlassStore = core.BreakGlassStore
type IdempotentCache = core.IdempotentCache
type PasswordCredentialStore = core.PasswordCredentialStore
type PasswordHashImporter = core.PasswordHashImporter
type PasswordCredentialDeleter = core.PasswordCredentialDeleter
type PasswordAgeReader = core.PasswordAgeReader
type MFAEnrollmentStore = core.MFAEnrollmentStore
type MFAEnrolledFactor = core.MFAEnrolledFactor
type TOTPEnrollmentWriter = core.TOTPEnrollmentWriter
type TOTPEnroller = core.TOTPEnroller
type RecoveryCodeStore = core.RecoveryCodeStore
type WebAuthnRegistrar = core.WebAuthnRegistrar
type TrustedDeviceStore = core.TrustedDeviceStore
type TrustedDevice = core.TrustedDevice
type DeviceSecretRevoker = core.DeviceSecretRevoker
type DeviceSecretStore = core.DeviceSecretStore
type DeviceSecret = core.DeviceSecret
type PasswordResetStore = core.PasswordResetStore
type PasswordResetToken = core.PasswordResetToken
type EmailChangeStore = core.EmailChangeStore
type EmailChangeToken = core.EmailChangeToken
type TokenMeta = core.TokenMeta
type User = core.User
type UserProvider = core.UserProvider

// --- Consts ---
const DefaultJWKSCacheMaxAge = core.DefaultJWKSCacheMaxAge
const PathJWKS = core.PathJWKS
const BearerPrefix = core.BearerPrefix
const ContentTypeJSON = core.ContentTypeJSON
const CORSAllowAllOrigin = core.CORSAllowAllOrigin
const CORSAllowedHeaders = core.CORSAllowedHeaders
const CORSAllowedMethods = core.CORSAllowedMethods
const DefaultAuthCodeTTL = core.DefaultAuthCodeTTL
const DefaultDeviceCodeTTL = core.DefaultDeviceCodeTTL
const DefaultDevicePollMin = core.DefaultDevicePollMin
const DefaultIssuer = core.DefaultIssuer
const DefaultRefreshTokenTTL = core.DefaultRefreshTokenTTL
const DefaultSessionDuration = core.DefaultSessionDuration
const DefaultTokenTTL = core.DefaultTokenTTL
const DepClientStore = core.DepClientStore
const DepSessionMgr = core.DepSessionMgr
const DepTokenIssuer = core.DepTokenIssuer
const DepUserProvider = core.DepUserProvider
const ErrAccessDenied = core.ErrAccessDenied
const ErrAccountLocked = core.ErrAccountLocked
const ErrAccountSelectionRequired = core.ErrAccountSelectionRequired
const ErrAuthCodeNotConfigured = core.ErrAuthCodeNotConfigured
const ErrAuthenticatorNotAllowed = core.ErrAuthenticatorNotAllowed
const ErrAuthorizationPending = core.ErrAuthorizationPending
const ErrCallbackFailed = core.ErrCallbackFailed
const ErrCIBANotConfigured = core.ErrCIBANotConfigured
const ErrUnknownUserID = core.ErrUnknownUserID
const ErrMissingUserCode = core.ErrMissingUserCode
const ErrClientNotFound = core.ErrClientNotFound
const ErrClientStoreNotConfigured = core.ErrClientStoreNotConfigured
const ErrConsentRequired = core.ErrConsentRequired
const ErrInvalidPassword = core.ErrInvalidPassword
const ErrDeviceCodeNotConfigured = core.ErrDeviceCodeNotConfigured
const ErrExpiredToken = core.ErrExpiredToken
const ErrInactiveClient = core.ErrInactiveClient
const ErrInteractionRequired = core.ErrInteractionRequired
const ErrInternal = core.ErrInternal
const ErrInvalidCallback = core.ErrInvalidCallback
const ErrInvalidClient = core.ErrInvalidClient
const ErrUnauthorizedClient = core.ErrUnauthorizedClient
const ErrInvalidCredentials = core.ErrInvalidCredentials
const ErrInvalidDPoPProof = core.ErrInvalidDPoPProof
const ErrInvalidGrant = core.ErrInvalidGrant
const ErrInvalidPKCEMethod = core.ErrInvalidPKCEMethod
const ErrInvalidRedirectURI = core.ErrInvalidRedirectURI
const ErrInvalidRequest = core.ErrInvalidRequest
const ErrInvalidRequestURI = core.ErrInvalidRequestURI
const ErrInvalidScope = core.ErrInvalidScope
const ErrInvalidTarget = core.ErrInvalidTarget
const ErrInvalidToken = core.ErrInvalidToken
const ErrLoginRequired = core.ErrLoginRequired
const ErrMFAInvalid = core.ErrMFAInvalid
const ErrMFARequired = core.ErrMFARequired
const ErrMissingClientID = core.ErrMissingClientID
const ErrMissingToken = core.ErrMissingToken
const ErrNetPolicyNotConfigured = core.ErrNetPolicyNotConfigured
const ErrNetPolicyNotFound = core.ErrNetPolicyNotFound
const ErrNoTokenStrategy = core.ErrNoTokenStrategy
const ErrPARNotConfigured = core.ErrPARNotConfigured
const ErrPayloadTooLarge = core.ErrPayloadTooLarge
const ErrPKCERequired = core.ErrPKCERequired
const ErrProviderAndTargetRequired = core.ErrProviderAndTargetRequired
const ErrProviderDoesNotSendCodes = core.ErrProviderDoesNotSendCodes
const ErrRefreshTokenNotConfigured = core.ErrRefreshTokenNotConfigured
const ErrRegionNotAllowed = core.ErrRegionNotAllowed
const ErrResidencyViolation = core.ErrResidencyViolation
const ErrRiskDenied = core.ErrRiskDenied
const ErrSAMLAssertionInvalid = core.ErrSAMLAssertionInvalid
const ErrSAMLRequestInvalid = core.ErrSAMLRequestInvalid
const ErrSAMLNotConfigured = core.ErrSAMLNotConfigured
const ErrSAMLAssertionFailed = core.ErrSAMLAssertionFailed
const ErrSendFailed = core.ErrSendFailed
const ErrResendTooSoon = core.ErrResendTooSoon
const ErrServerMisconfigured = core.ErrServerMisconfigured
const ErrSessionIDOrBearerRequired = core.ErrSessionIDOrBearerRequired
const ErrSessionMgrNotConfigured = core.ErrSessionMgrNotConfigured
const ErrSlowDown = core.ErrSlowDown
const ErrTenantMismatch = core.ErrTenantMismatch
const ErrUnauthorized = core.ErrUnauthorized
const ErrUnknownProvider = core.ErrUnknownProvider
const ErrUnmetAuthReqs = core.ErrUnmetAuthReqs
const ErrUnsupportedGrantType = core.ErrUnsupportedGrantType
const ErrUnsupportedProvider = core.ErrUnsupportedProvider
const ErrUnsupportedResponseType = core.ErrUnsupportedResponseType
const ErrUseDPoPNonce = core.ErrUseDPoPNonce
const ErrEmailNotVerified = core.ErrEmailNotVerified
const ErrNotFound = core.ErrNotFound
const ErrCompromiseReasonRequired = core.ErrCompromiseReasonRequired
const ErrCredentialCompromiseUnsupported = core.ErrCredentialCompromiseUnsupported
const ErrNotSupported = core.ErrNotSupported
const ErrUserNotFound = core.ErrUserNotFound
const GrantAuthorizationCode = core.GrantAuthorizationCode
const GrantClientCredentials = core.GrantClientCredentials
const GrantDeviceCode = core.GrantDeviceCode
const GrantRefreshToken = core.GrantRefreshToken
const GrantTokenExchange = core.GrantTokenExchange
const GrantCIBA = core.GrantCIBA
const GrantJWTBearer = core.GrantJWTBearer
const GrantTypeSAML2Bearer = core.GrantTypeSAML2Bearer
const HeaderAccessControlHeaders = core.HeaderAccessControlHeaders
const HeaderAccessControlMethods = core.HeaderAccessControlMethods
const HeaderAccessControlOrigin = core.HeaderAccessControlOrigin
const HeaderAuthorization = core.HeaderAuthorization
const HeaderAuthSubject = core.HeaderAuthSubject
const HeaderAuthClientID = core.HeaderAuthClientID
const HeaderAuthScopes = core.HeaderAuthScopes
const HeaderAuthExpires = core.HeaderAuthExpires
const HeaderAuthRoles = core.HeaderAuthRoles
const HeaderContentType = core.HeaderContentType
const HeaderParentSpanID = core.HeaderParentSpanID
const HeaderRequestID = core.HeaderRequestID
const HeaderTraceparent = core.HeaderTraceparent

// The KeyAccessToken..KeyVersion block relocated to origin_validation.go to
// keep this generated file within the per-file line budget (this file has no
// natural internal grouping to split on otherwise).
const PathAPIPrefix = core.PathAPIPrefix
const PathAuthzPolicyBundle = core.PathAuthzPolicyBundle
const PathStorageHealth = core.PathStorageHealth
const PathTenantUsage = core.PathTenantUsage
const PathAdminTopTenants = core.PathAdminTopTenants
const PathAdminTokenUsage = core.PathAdminTokenUsage
const PathAdminTokenPolicies = core.PathAdminTokenPolicies
const PathAdminAccessPolicies = core.PathAdminAccessPolicies
const PathAdminUserConsents = core.PathAdminUserConsents
const PathAdminUserConsentByID = core.PathAdminUserConsentByID
const PathAdminUserMFA = core.PathAdminUserMFA
const PathAdminUserMFAByID = core.PathAdminUserMFAByID
const PathAdminUserLifecycle = core.PathAdminUserLifecycle
const PathAdminUserRecoveryCodes = core.PathAdminUserRecoveryCodes
const PathAdminUserPassword = core.PathAdminUserPassword
const PathAdminUserDeviceSecrets = core.PathAdminUserDeviceSecrets
const PathAdminUserRefreshTokens = core.PathAdminUserRefreshTokens
const PathAdminUserPasswordResetTokens = core.PathAdminUserPasswordResetTokens
const PathAdminUserEmailChangeTokens = core.PathAdminUserEmailChangeTokens
const PathAdminLocalUserByID = core.PathAdminLocalUserByID
const PathAdminLocalUsers = core.PathAdminLocalUsers
const PathBackup = core.PathBackup
const PathAdminUserEmail = core.PathAdminUserEmail
const PathAdminAccountLockoutClear = core.PathAdminAccountLockoutClear
const PathAdminEndpoints = core.PathAdminEndpoints
const PathAdminTokens = core.PathAdminTokens
const PathAdminTokenByID = core.PathAdminTokenByID
const PathAdminLogout = core.PathAdminLogout
const PathAdminSessions = core.PathAdminSessions
const PathAdminCredentials = core.PathAdminCredentials
const PathAdminCredentialCompromise = core.PathAdminCredentialCompromise
const PathAdminEventsStream = core.PathAdminEventsStream

// Crypto-material-inventory admin route-path re-exports, relocated here from
// server_routes_admin.go (which ran out of room adding the wasmauthz mount).
const PathAdminCryptoKeys = core.PathAdminCryptoKeys
const PathAdminCryptoKeyCompromise = core.PathAdminCryptoKeyCompromise

const PathAdminBreakGlass = core.PathAdminBreakGlass
const PathAdminBreakGlassByID = core.PathAdminBreakGlassByID
const PathAdminBreakGlassApprove = core.PathAdminBreakGlassApprove
const PathAdminBreakGlassImpersonate = core.PathAdminBreakGlassImpersonate
const PathAdminConnections = core.PathAdminConnections
const PathAdminConnectionByID = core.PathAdminConnectionByID
const PathAdminConnectionDomains = core.PathAdminConnectionDomains
const PathAdminConnectionDomainVerify = core.PathAdminConnectionDomainVerify
const PathAdminConnectionHealth = core.PathAdminConnectionHealth
const PathAdminConnectionProbe = core.PathAdminConnectionProbe
const PathAdminTenantMembers = core.PathAdminTenantMembers
const PathAdminTenantMemberByID = core.PathAdminTenantMemberByID
const PathAdminTenantExport = core.PathAdminTenantExport
const PathMyOrganizations = core.PathMyOrganizations
const PathMyOrganizationByID = core.PathMyOrganizationByID
const PathAdminTenantInvitations = core.PathAdminTenantInvitations
const PathAdminTenantInvitationByEmail = core.PathAdminTenantInvitationByEmail
const PathMyInvitationAccept = core.PathMyInvitationAccept
const PathOrgAdminMembers = core.PathOrgAdminMembers
const PathOrgAdminMemberByID = core.PathOrgAdminMemberByID
const PathOrgAdminInvitations = core.PathOrgAdminInvitations
const PathOrgAdminInvitationByEmail = core.PathOrgAdminInvitationByEmail
const PathSSFReceive = core.PathSSFReceive
const PathFederationEntityConfig = core.PathFederationEntityConfig
const PathFederationFetch = core.PathFederationFetch
const PathAuditEventByID = core.PathAuditEventByID
const PathAuditEvents = core.PathAuditEvents
const PathAuditFacets = core.PathAuditFacets
const PathAdminConfigRunning = core.PathAdminConfigRunning
const PathAdminConfigApplied = core.PathAdminConfigApplied
const PathAdminConfigDiff = core.PathAdminConfigDiff
const PathAdminConfigHistory = core.PathAdminConfigHistory
const PathAdminConfigClusterDiff = core.PathAdminConfigClusterDiff
const PathCallback = core.PathCallback
const PathClientByID = core.PathClientByID
const PathDeviceCode = core.PathDeviceCode
const PathDeviceVerify = core.PathDeviceVerify
const PathEndSession = core.PathEndSession
const PathHealth = core.PathHealth
const PathIntrospect = core.PathIntrospect
const PathLivez = core.PathLivez
const PathLogin = core.PathLogin
const PathLogout = core.PathLogout
const PathMFAComplete = core.PathMFAComplete
const PathMyMenus = core.PathMyMenus
const PathMyPermissions = core.PathMyPermissions
const PathMyRoles = core.PathMyRoles
const PathMySessions = core.PathMySessions
const PathMySessionByID = core.PathMySessionByID
const PathMeSessions = core.PathMeSessions
const PathMeSessionByID = core.PathMeSessionByID
const PathMeSessionsRevokeAll = core.PathMeSessionsRevokeAll
const PathMyConsents = core.PathMyConsents
const PathMyConsentByID = core.PathMyConsentByID
const PathBranding = core.PathBranding
const PathProtectedResourceMetadata = core.PathProtectedResourceMetadata
const PathOAuthAuthorizationServerMetadata = core.PathOAuthAuthorizationServerMetadata
const PathMe = core.PathMe
const PathMyPassword = core.PathMyPassword
const PathMyMFA = core.PathMyMFA
const PathMyMFAByID = core.PathMyMFAByID
const PathMyMFATOTPBegin = core.PathMyMFATOTPBegin
const PathMyMFATOTPConfirm = core.PathMyMFATOTPConfirm
const PathMyMFARecoveryCodes = core.PathMyMFARecoveryCodes
const PathForgotPassword = core.PathForgotPassword
const PathResetPassword = core.PathResetPassword
const PathSignup = core.PathSignup
const PathVerifyEmail = core.PathVerifyEmail
const PathMyDataExport = core.PathMyDataExport
const PathMyAccountErase = core.PathMyAccountErase
const PathMyEmailChange = core.PathMyEmailChange
const PathMyEmailVerify = core.PathMyEmailVerify
const PathMyWebAuthnRegisterBegin = core.PathMyWebAuthnRegisterBegin
const PathMyWebAuthnRegisterFinish = core.PathMyWebAuthnRegisterFinish
const PathMyDevices = core.PathMyDevices
const PathMyDeviceByID = core.PathMyDeviceByID
const PathMyDevicesTrust = core.PathMyDevicesTrust
const PKCEMethodPlain = core.PKCEMethodPlain
const PKCEMethodS256 = core.PKCEMethodS256
const PKCEVerifierMaxLen = core.PKCEVerifierMaxLen
const PKCEVerifierMinLen = core.PKCEVerifierMinLen
const PromptConsent = core.PromptConsent
const PromptLogin = core.PromptLogin
const PromptNone = core.PromptNone
const PromptSelectAccount = core.PromptSelectAccount
const RevokedSession = core.RevokedSession
const RevokedToken = core.RevokedToken
const ScopeOpenID = core.ScopeOpenID
const ScopeDeviceSSO = core.ScopeDeviceSSO
const KeyDeviceSecret = core.KeyDeviceSecret
const KeyDsHash = core.KeyDsHash
const TokenTypeDeviceSecret = core.TokenTypeDeviceSecret
const DefaultDeviceSecretTTL = core.DefaultDeviceSecretTTL
const ErrDeviceSecretNotConfigured = core.ErrDeviceSecretNotConfigured
const StatusAuthenticated = core.StatusAuthenticated
const StatusLoggedOut = core.StatusLoggedOut
const StatusOK = core.StatusOK
const StatusSent = core.StatusSent
const TokenStrategyJWT = core.TokenStrategyJWT
const TokenStrategySession = core.TokenStrategySession
const TokenTypeAccessToken = core.TokenTypeAccessToken
const TokenTypeBearer = core.TokenTypeBearer
const TokenTypeIDToken = core.TokenTypeIDToken
const TokenTypeJWT = core.TokenTypeJWT
const TokenTypeNameBearer = core.TokenTypeNameBearer
const TokenTypeNameDPoP = core.TokenTypeNameDPoP
const TokenTypeRefreshToken = core.TokenTypeRefreshToken
const TokenTypeSAML2 = core.TokenTypeSAML2

// --- Vars ---
var SupportedGrants = core.SupportedGrants
var ErrClientExists = core.ErrClientExists
var ErrNoConsentGrant = core.ErrNoConsentGrant
var ErrNoMembership = core.ErrNoMembership
var ErrInvitationNotFound = core.ErrInvitationNotFound

// TenantRole values (B2B org membership standing).
const (
	TenantRoleMember = core.TenantRoleMember
	TenantRoleAdmin  = core.TenantRoleAdmin
	TenantRoleGuest  = core.TenantRoleGuest
)

var ErrPasswordMismatch = core.ErrPasswordMismatch
var ErrNoSuchClient = core.ErrNoSuchClient
var ErrNoSuchUser = core.ErrNoSuchUser
var ErrDeviceSecretNotFound = core.ErrDeviceSecretNotFound
var ErrSessionNotFound = core.ErrSessionNotFound
var ErrUnsupportedOperation = core.ErrUnsupportedOperation
var ErrUserExists = core.ErrUserExists

// --- Funcs ---
var NewContext = core.NewContext
var NewStdRouter = core.NewStdRouter

// NewHMACNonceProvider re-exported from internal/handler.
var NewHMACNonceProvider = handler.NewHMACNonceProvider
var NewHMACNonceProviderWithKey = handler.NewHMACNonceProviderWithKey

type HMACNonceProvider = handler.HMACNonceProvider

// StorageHealthSource re-exported from internal/handler.
type StorageHealthSource = handler.StorageHealthSource

// Active ITDR threat-policy admin route-path re-exports.
const PathAdminThreatPolicies = core.PathAdminThreatPolicies
const PathAdminThreatPolicyByID = core.PathAdminThreatPolicyByID
