package security

// JWS verification, SPIFFE/SVID validation, JAR fetching, step-up challenge
// building and mTLS header-cert extraction live in the securityverify leaf so
// this directory stays within the per-directory file-count budget. These
// aliases preserve the historical security.* import surface unchanged for every
// consumer (oauth/oidc validation, the Server, the signing backends). Type
// aliases keep interface/struct identity so external implementations stay valid.

import "github.com/snaplink/sso/shared/security/securityverify"

type (
	HeaderCertEncoding        = securityverify.HeaderCertEncoding
	HeaderClientCertExtractor = securityverify.HeaderClientCertExtractor
	JARFetcher                = securityverify.JARFetcher
	HTTPJARFetcher            = securityverify.HTTPJARFetcher
	StepUpChallenge           = securityverify.StepUpChallenge
	SPIFFEID                  = securityverify.SPIFFEID
	JWKSSource                = securityverify.JWKSSource
	StaticJWKS                = securityverify.StaticJWKS
	SPIFFEValidator           = securityverify.SPIFFEValidator
	SPIFFEValidatorOption     = securityverify.SPIFFEValidatorOption
)

const (
	DefaultJARFetchTimeout      = securityverify.DefaultJARFetchTimeout
	DefaultJARFetchMaxBytes     = securityverify.DefaultJARFetchMaxBytes
	DefaultSPIFFEMaxClockSkew   = securityverify.DefaultSPIFFEMaxClockSkew
	AttrSPIFFEID                = securityverify.AttrSPIFFEID
	AttrSPIFFENamespace         = securityverify.AttrSPIFFENamespace
	AttrSPIFFEServiceAccount    = securityverify.AttrSPIFFEServiceAccount
	AttrSPIFFETrustDomain       = securityverify.AttrSPIFFETrustDomain
	HeaderCertEncodingPEM       = securityverify.HeaderCertEncodingPEM
	HeaderCertEncodingBase64DER = securityverify.HeaderCertEncodingBase64DER
	HeaderCertEncodingURLPEM    = securityverify.HeaderCertEncodingURLPEM

	WebhookSignatureHeader           = securityverify.WebhookSignatureHeader
	DefaultWebhookSignatureTolerance = securityverify.DefaultWebhookSignatureTolerance
)

var (
	ErrSPIFFESVIDInvalid              = securityverify.ErrSPIFFESVIDInvalid
	ErrInsufficientUserAuthentication = securityverify.ErrInsufficientUserAuthentication

	ParseSPIFFEURI               = securityverify.ParseSPIFFEURI
	NewStaticJWKS                = securityverify.NewStaticJWKS
	ParseStaticJWKS              = securityverify.ParseStaticJWKS
	WithSPIFFEMaxClockSkew       = securityverify.WithSPIFFEMaxClockSkew
	WithSPIFFEAllowedAlgs        = securityverify.WithSPIFFEAllowedAlgs
	NewSPIFFEValidator           = securityverify.NewSPIFFEValidator
	NewHTTPJARFetcher            = securityverify.NewHTTPJARFetcher
	IsJARFetchableURI            = securityverify.IsJARFetchableURI
	IsRequestURIAllowed          = securityverify.IsRequestURIAllowed
	VerifyCompactJWS             = securityverify.VerifyCompactJWS
	AsymmetricJWSAlgs            = securityverify.AsymmetricJWSAlgs
	AsymmetricJWSAlgValues       = securityverify.AsymmetricJWSAlgValues
	NewHeaderClientCertExtractor = securityverify.NewHeaderClientCertExtractor
	BuildStepUpChallenge         = securityverify.BuildStepUpChallenge
	QuoteAuthParam               = securityverify.QuoteAuthParam
	MustBuildStepUpChallenge     = securityverify.MustBuildStepUpChallenge

	SignWebhookPayload           = securityverify.SignWebhookPayload
	VerifyWebhookSignature       = securityverify.VerifyWebhookSignature
	ErrWebhookSignatureMalformed = securityverify.ErrWebhookSignatureMalformed
	ErrWebhookSignatureMismatch  = securityverify.ErrWebhookSignatureMismatch
	ErrWebhookSignatureExpired   = securityverify.ErrWebhookSignatureExpired
)
