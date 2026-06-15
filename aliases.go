// Code generated. Backward-compat re-exports of core package symbols.
package sso

import (
	"github.com/snaplink/sso/admin"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/fapi"
	"github.com/snaplink/sso/geo"
	"github.com/snaplink/sso/middleware"
	"github.com/snaplink/sso/tenant"
	"github.com/snaplink/sso/internal/handler"
)

// FAPIMode re-exports fapi.Mode so callers configure WithFAPIProfile
// without importing the fapi package directly.
type FAPIMode = fapi.Mode

const (
	FAPIModeOff        = fapi.ModeOff
	FAPIModeInspection = fapi.ModeInspection
	FAPIModeEnforce    = fapi.ModeEnforce
)

// --- General middleware re-exports (functions moved to middleware/) ---
var AuthMiddleware = middleware.Auth
var CORS = middleware.CORS
var LoggerMiddleware = middleware.Logger
var TracingMiddleware = middleware.Tracing
var RequestIDMiddleware = middleware.RequestID

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
type AuthRequest = core.AuthRequest
type AuthResult = core.AuthResult
type CredentialHealth = core.CredentialHealth
type CallbackState = core.CallbackState
type Client = core.Client
type ClientStore = core.ClientStore
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
type PasswordCredentialStore = core.PasswordCredentialStore
type PasswordHashImporter = core.PasswordHashImporter
type MFAEnrollmentStore = core.MFAEnrollmentStore
type MFAEnrolledFactor = core.MFAEnrolledFactor
type TOTPEnrollmentWriter = core.TOTPEnrollmentWriter
type TOTPEnroller = core.TOTPEnroller
type WebAuthnRegistrar = core.WebAuthnRegistrar
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
const ErrNotFound = core.ErrNotFound
const ErrNotSupported = core.ErrNotSupported
const ErrUserNotFound = core.ErrUserNotFound
const GrantAuthorizationCode = core.GrantAuthorizationCode
const GrantClientCredentials = core.GrantClientCredentials
const GrantDeviceCode = core.GrantDeviceCode
const GrantRefreshToken = core.GrantRefreshToken
const GrantTokenExchange = core.GrantTokenExchange
const GrantCIBA = core.GrantCIBA
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
const KeyAccessToken = core.KeyAccessToken
const KeyACR = core.KeyACR
const KeyActive = core.KeyActive
const KeyAMR = core.KeyAMR
const KeyAud = core.KeyAud
const KeyAuthTime = core.KeyAuthTime
const KeyClientID = core.KeyClientID
const KeyTenantID = core.KeyTenantID
const KeyClientName = core.KeyClientName
const KeyScopes = core.KeyScopes
const KeyCode = core.KeyCode
const KeyCountryCode = core.KeyCountryCode
const KeyError = core.KeyError
const KeyErrorDescription = core.KeyErrorDescription
const KeyExp = core.KeyExp
const KeyExpiresIn = core.KeyExpiresIn
const KeyIat = core.KeyIat
const KeyIDToken = core.KeyIDToken
const KeyIss = core.KeyIss
const KeyIssuedTokenType = core.KeyIssuedTokenType
const KeyIssuer = core.KeyIssuer
const KeyJTI = core.KeyJTI
const KeyConsentChallengeID = core.KeyConsentChallengeID
const KeyMFAChallengeID = core.KeyMFAChallengeID
const KeyMFAMethod = core.KeyMFAMethod
const KeyMFAMethodData = core.KeyMFAMethodData
const KeyMFAMethods = core.KeyMFAMethods
const KeyNbf = core.KeyNbf
const KeyProviders = core.KeyProviders
const KeyRecommendedLang = core.KeyRecommendedLang
const KeyRedirectURI = core.KeyRedirectURI
const KeyRefreshToken = core.KeyRefreshToken
const KeyRevoked = core.KeyRevoked
const KeyScope = core.KeyScope
const KeyServingRegion = core.KeyServingRegion
const KeySessionID = core.KeySessionID
const KeyState = core.KeyState
const KeyStatus = core.KeyStatus
const KeyStrategy = core.KeyStrategy
const KeySub = core.KeySub
const KeySupportedGrants = core.KeySupportedGrants
const KeyTokenHint = core.KeyTokenHint
const KeyTokenStrategy = core.KeyTokenStrategy
const KeyTokenType = core.KeyTokenType
const KeyVCSRevision = core.KeyVCSRevision
const KeyVCSTime = core.KeyVCSTime
const KeyVersion = core.KeyVersion
const PathAPIPrefix = core.PathAPIPrefix
const PathAuthzPolicyBundle = core.PathAuthzPolicyBundle
const PathStorageHealth = core.PathStorageHealth
const PathTenantUsage = core.PathTenantUsage
const PathAdminUserConsents = core.PathAdminUserConsents
const PathAdminUserConsentByID = core.PathAdminUserConsentByID
const PathAdminUserMFA = core.PathAdminUserMFA
const PathAdminUserMFAByID = core.PathAdminUserMFAByID
const PathAdminUserPassword = core.PathAdminUserPassword
const PathAdminUserDeviceSecrets = core.PathAdminUserDeviceSecrets
const PathAdminUserPasswordResetTokens = core.PathAdminUserPasswordResetTokens
const PathAdminUserEmailChangeTokens = core.PathAdminUserEmailChangeTokens
const PathAdminUserEmail = core.PathAdminUserEmail
const PathAdminAccountLockoutClear = core.PathAdminAccountLockoutClear
const PathAdminConnections = core.PathAdminConnections
const PathAdminConnectionByID = core.PathAdminConnectionByID
const PathAdminTenantMembers = core.PathAdminTenantMembers
const PathAdminTenantMemberByID = core.PathAdminTenantMemberByID
const PathMyOrganizations = core.PathMyOrganizations
const PathMyOrganizationByID = core.PathMyOrganizationByID
const PathAdminTenantInvitations = core.PathAdminTenantInvitations
const PathMyInvitationAccept = core.PathMyInvitationAccept
const PathSSFReceive = core.PathSSFReceive
const PathFederationEntityConfig = core.PathFederationEntityConfig
const PathFederationFetch = core.PathFederationFetch
const PathAuditEventByID = core.PathAuditEventByID
const PathAuditEvents = core.PathAuditEvents
const PathAuditFacets = core.PathAuditFacets
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
const PathMyConsents = core.PathMyConsents
const PathMyConsentByID = core.PathMyConsentByID
const PathBranding = core.PathBranding
const PathProtectedResourceMetadata = core.PathProtectedResourceMetadata
const PathMe = core.PathMe
const PathMyPassword = core.PathMyPassword
const PathMyMFA = core.PathMyMFA
const PathMyMFAByID = core.PathMyMFAByID
const PathMyMFATOTPBegin = core.PathMyMFATOTPBegin
const PathMyMFATOTPConfirm = core.PathMyMFATOTPConfirm
const PathForgotPassword = core.PathForgotPassword
const PathResetPassword = core.PathResetPassword
const PathSignup = core.PathSignup
const PathMyDataExport = core.PathMyDataExport
const PathMyAccountErase = core.PathMyAccountErase
const PathMyEmailChange = core.PathMyEmailChange
const PathMyEmailVerify = core.PathMyEmailVerify
const PathMyWebAuthnRegisterBegin = core.PathMyWebAuthnRegisterBegin
const PathMyWebAuthnRegisterFinish = core.PathMyWebAuthnRegisterFinish
const PathMeshExtAuthz = core.PathMeshExtAuthz
const PathNetPolicies = core.PathNetPolicies
const PathNetPolicyByName = core.PathNetPolicyByName
const PathNetPolicyClassify = core.PathNetPolicyClassify
const PathNetPolicyResolveMe = core.PathNetPolicyResolveMe
const PathPAR = core.PathPAR
const PathBackchannelAuth = core.PathBackchannelAuth
const PathReadyz = core.PathReadyz
const PathRevoke = core.PathRevoke
const PathRevokeAll = core.PathRevokeAll
const PathSAMLMetadata = core.PathSAMLMetadata
const PathSAMLSSO = core.PathSAMLSSO
const PathSAMLSSOCallback = core.PathSAMLSSOCallback
const PathSAMLSLO = core.PathSAMLSLO
const PathSAMLSLOContinue = core.PathSAMLSLOContinue
const PathSAMLSPSLO = core.PathSAMLSPSLO
const PathSendCode = core.PathSendCode
const PathToken = core.PathToken
const PathUserInfo = core.PathUserInfo
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
