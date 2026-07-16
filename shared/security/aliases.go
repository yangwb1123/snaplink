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

	RotatingWebhookSecret = securityverify.RotatingWebhookSecret
	WebhookSecretRotator  = securityverify.WebhookSecretRotator

	CloudProvider                   = securityverify.CloudProvider
	WorkloadIdentity                = securityverify.WorkloadIdentity
	WorkloadIdentityProvider        = securityverify.WorkloadIdentityProvider
	WorkloadIdentityValidator       = securityverify.WorkloadIdentityValidator
	WorkloadIdentityValidatorOption = securityverify.WorkloadIdentityValidatorOption
	HTTPJWKSSource                  = securityverify.HTTPJWKSSource
	HTTPJWKSSourceOption            = securityverify.HTTPJWKSSourceOption
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
	WebhookSecretBytes               = securityverify.WebhookSecretBytes

	DefaultWorkloadIdentityMaxClockSkew = securityverify.DefaultWorkloadIdentityMaxClockSkew
	DefaultJWKSCacheTTL                 = securityverify.DefaultJWKSCacheTTL
	DefaultJWKSMaxStaleAge              = securityverify.DefaultJWKSMaxStaleAge
	AttrWorkloadIdentityProvider        = securityverify.AttrWorkloadIdentityProvider
	AttrWorkloadIdentitySubject         = securityverify.AttrWorkloadIdentitySubject
	AttrGCPProjectID                    = securityverify.AttrGCPProjectID
	AttrGCPServiceAccount               = securityverify.AttrGCPServiceAccount
	AttrGCPInstanceName                 = securityverify.AttrGCPInstanceName
	AttrGCPZone                         = securityverify.AttrGCPZone
	GCPIssuer                           = securityverify.GCPIssuer
	GCPJWKSURL                          = securityverify.GCPJWKSURL
	CloudProviderGCP                    = securityverify.CloudProviderGCP
	CloudProviderAWS                    = securityverify.CloudProviderAWS
	CloudProviderAzure                  = securityverify.CloudProviderAzure
	AttrAWSNamespace                    = securityverify.AttrAWSNamespace
	AttrAWSServiceAccountName           = securityverify.AttrAWSServiceAccountName
	AttrAWSServiceAccountUID            = securityverify.AttrAWSServiceAccountUID
	AttrAzureTenantID                   = securityverify.AttrAzureTenantID
	AttrAzureAppID                      = securityverify.AttrAzureAppID
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

	NewRotatingWebhookSecret = securityverify.NewRotatingWebhookSecret
	NewWebhookSecretRotator  = securityverify.NewWebhookSecretRotator

	ErrWorkloadIdentityInvalid        = securityverify.ErrWorkloadIdentityInvalid
	NewWorkloadIdentityValidator      = securityverify.NewWorkloadIdentityValidator
	NewGCPWorkloadIdentityValidator   = securityverify.NewGCPWorkloadIdentityValidator
	NewAWSWorkloadIdentityValidator   = securityverify.NewAWSWorkloadIdentityValidator
	NewAzureWorkloadIdentityValidator = securityverify.NewAzureWorkloadIdentityValidator
	NewHTTPJWKSSource                 = securityverify.NewHTTPJWKSSource
	WithWorkloadIdentityMaxClockSkew  = securityverify.WithWorkloadIdentityMaxClockSkew
	WithWorkloadIdentityAllowedAlgs   = securityverify.WithWorkloadIdentityAllowedAlgs
	WithJWKSCacheTTL                  = securityverify.WithJWKSCacheTTL
	WithJWKSMaxStaleAge               = securityverify.WithJWKSMaxStaleAge
	WithJWKSHTTPClient                = securityverify.WithJWKSHTTPClient
)
