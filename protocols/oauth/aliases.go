package oauth

// The OAuth grant-record SPIs (oauthspi), wire/PKCE primitives (oauthwire) and
// request validators (oauthvalidate) live in leaf sub-packages so this directory
// stays within the per-directory file-count budget. The hexagonal Handle* grant
// handlers stay here and reference the moved symbols through these re-exports, so
// every public oauth.* import-path symbol is preserved unchanged for the ~60
// external importers (storage backends implement the store SPIs; interfaces/sso
// wires the handlers). Type aliases keep interface/struct identity intact.

import (
	"github.com/snaplink/sso/protocols/oauth/oauthspi"
	"github.com/snaplink/sso/protocols/oauth/oauthvalidate"
	"github.com/snaplink/sso/protocols/oauth/oauthwire"
)

type (
	AuthCode                    = oauthspi.AuthCode
	AuthCodeStore               = oauthspi.AuthCodeStore
	RefreshToken                = oauthspi.RefreshToken
	RefreshAuthContext          = oauthspi.RefreshAuthContext
	RefreshTokenStore           = oauthspi.RefreshTokenStore
	RefreshTokenInspector       = oauthspi.RefreshTokenInspector
	RefreshTokenSubjectIndex    = oauthspi.RefreshTokenSubjectIndex
	RefreshTokenSubjectCounter  = oauthspi.RefreshTokenSubjectCounter
	RefreshTokenClientPurger    = oauthspi.RefreshTokenClientPurger
	RefreshTokenFamilyTracker   = oauthspi.RefreshTokenFamilyTracker
	RefreshTokenRotationLimiter = oauthspi.RefreshTokenRotationLimiter
	DeviceCode                  = oauthspi.DeviceCode
	DeviceCodeStore             = oauthspi.DeviceCodeStore
	PARRequest                  = oauthspi.PARRequest
	PARStore                    = oauthspi.PARStore
	CIBAStatus                  = oauthspi.CIBAStatus
	CIBARequest                 = oauthspi.CIBARequest
	CIBAStore                   = oauthspi.CIBAStore
	CIBATransport               = oauthspi.CIBATransport
	CIBAPingNotifier            = oauthspi.CIBAPingNotifier
	CIBAPingNotifierFunc        = oauthspi.CIBAPingNotifierFunc
	CIBATransportFunc           = oauthspi.CIBATransportFunc
	IssueAuthCodeParams         = oauthwire.IssueAuthCodeParams
	IssueRefreshTokenParams     = oauthwire.IssueRefreshTokenParams
	TokenRequest                = oauthwire.TokenRequest
	DCRMetadata                 = oauthvalidate.DCRMetadata
	DCRPolicy                   = oauthvalidate.DCRPolicy
	ClaimRequest                = oauthvalidate.ClaimRequest
	RARLimits                   = oauthvalidate.RARLimits
)

const (
	UserCodeAlphabet               = oauthspi.UserCodeAlphabet
	DefaultPARTTL                  = oauthspi.DefaultPARTTL
	PARURIPrefix                   = oauthspi.PARURIPrefix
	GrantCIBA                      = oauthspi.GrantCIBA
	AuthReqIDPrefix                = oauthspi.AuthReqIDPrefix
	DefaultCIBARequestTTL          = oauthspi.DefaultCIBARequestTTL
	DefaultCIBAPollInterval        = oauthspi.DefaultCIBAPollInterval
	CIBAPending                    = oauthspi.CIBAPending
	CIBAApproved                   = oauthspi.CIBAApproved
	CIBADenied                     = oauthspi.CIBADenied
	PKCEMethodPlain                = oauthwire.PKCEMethodPlain
	PKCEMethodS256                 = oauthwire.PKCEMethodS256
	DefaultJWEResponseEnc          = oauthvalidate.DefaultJWEResponseEnc
	PathRegister                   = oauthvalidate.PathRegister
	PathRegisterByID               = oauthvalidate.PathRegisterByID
	ErrInvalidClientMetadata       = oauthvalidate.ErrInvalidClientMetadata
	ErrRegistrationDisabled        = oauthvalidate.ErrRegistrationDisabled
	KeyAuthorizationDetails        = oauthvalidate.KeyAuthorizationDetails
	ErrInvalidAuthorizationDetails = oauthvalidate.ErrInvalidAuthorizationDetails
	MetaKeyDCRMethod               = oauthvalidate.MetaKeyDCRMethod
	DCRMethodInitialAccessToken    = oauthvalidate.DCRMethodInitialAccessToken
	DCRMethodOpen                  = oauthvalidate.DCRMethodOpen
)

var (
	ErrAuthCodeNotFound          = oauthspi.ErrAuthCodeNotFound
	ErrRefreshTokenNotFound      = oauthspi.ErrRefreshTokenNotFound
	ErrRefreshTokenReused        = oauthspi.ErrRefreshTokenReused
	ErrDeviceCodeNotFound        = oauthspi.ErrDeviceCodeNotFound
	GenerateDeviceCode           = oauthspi.GenerateDeviceCode
	GenerateUserCode             = oauthspi.GenerateUserCode
	NormalizeUserCode            = oauthspi.NormalizeUserCode
	ErrPARNotFound               = oauthspi.ErrPARNotFound
	ErrCIBARequestNotFound       = oauthspi.ErrCIBARequestNotFound
	ErrCIBARequestInvalid        = oauthspi.ErrCIBARequestInvalid
	ErrCIBARequestResolved       = oauthspi.ErrCIBARequestResolved
	BindParams                   = oauthwire.BindParams
	BearerToken                  = oauthwire.BearerToken
	BasicClientCreds             = oauthwire.BasicClientCreds
	IsSecureRedirectURI          = oauthwire.IsSecureRedirectURI
	IsValidPKCEMethod            = oauthwire.IsValidPKCEMethod
	IsPKCEMethodAllowedForClient = oauthwire.IsPKCEMethodAllowedForClient
	VerifyPKCE                   = oauthwire.VerifyPKCE
	GenerateAuthCodeBytes        = oauthwire.GenerateAuthCodeBytes
	IsScopeSubset                = oauthwire.IsScopeSubset
	IssueAuthCode                = oauthwire.IssueAuthCode
	IssueRefreshToken            = oauthwire.IssueRefreshToken
	ACRMatchesAny                = oauthwire.ACRMatchesAny
	MergeTargets                 = oauthwire.MergeTargets
	ValidateDCRMetadata          = oauthvalidate.ValidateDCRMetadata
	ErrDCR                       = oauthvalidate.ErrDCR
	ErrDCRBadMetadata            = oauthvalidate.ErrDCRBadMetadata
	GenerateClientID             = oauthvalidate.GenerateClientID
	GenerateClientSecret         = oauthvalidate.GenerateClientSecret
	CloneRawJSON                 = oauthvalidate.CloneRawJSON
	ValidateAuthorizationDetails = oauthvalidate.ValidateAuthorizationDetails
	ErrScopeNotAllowed           = oauthvalidate.ErrScopeNotAllowed
	JoinScope                    = oauthvalidate.JoinScope
	SplitScope                   = oauthvalidate.SplitScope
	GrantedScopes                = oauthvalidate.GrantedScopes
	ParseRequestedClaims         = oauthvalidate.ParseRequestedClaims
	ValidateClaimsParameter      = oauthvalidate.ValidateClaimsParameter
	RequestedACRFromClaims       = oauthvalidate.RequestedACRFromClaims
	IsValidResponseMode          = oauthvalidate.IsValidResponseMode
)
