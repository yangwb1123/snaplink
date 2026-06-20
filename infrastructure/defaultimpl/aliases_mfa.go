package defaultimpl

// The MFA providers and stores (composite/multi enrollment, memory MFA-challenge
// / enrollment / TOTP / push-approval stores, the push-MFA provider and its
// webhook transport) live in the defaultmfa leaf so this directory stays within
// the per-directory file-count budget. defaultmfa depends on shared/core
// directly (not the interfaces/sso facade), removing a latent upward import.
// These aliases preserve the historical defaultimpl.* import surface unchanged.

import "github.com/snaplink/sso/infrastructure/defaultimpl/defaultmfa"

type (
	CompositeMFAEnrollmentStore = defaultmfa.CompositeMFAEnrollmentStore
	HTTPWebhookPushTransport    = defaultmfa.HTTPWebhookPushTransport
	MemoryMFAChallengeStore     = defaultmfa.MemoryMFAChallengeStore
	MemoryMFAEnrollmentStore    = defaultmfa.MemoryMFAEnrollmentStore
	MemoryPushApprovalStore     = defaultmfa.MemoryPushApprovalStore
	MemoryTOTPEnrollmentStore   = defaultmfa.MemoryTOTPEnrollmentStore
	MultiMFAProvider            = defaultmfa.MultiMFAProvider
	PushApproval                = defaultmfa.PushApproval
	PushApprovalStatus          = defaultmfa.PushApprovalStatus
	PushApprovalStore           = defaultmfa.PushApprovalStore
	PushMFAOption               = defaultmfa.PushMFAOption
	PushMFAProvider             = defaultmfa.PushMFAProvider
	PushTransport               = defaultmfa.PushTransport
	PushTransportFunc           = defaultmfa.PushTransportFunc
	PushWebhookOption           = defaultmfa.PushWebhookOption
)

const (
	MethodPush           = defaultmfa.MethodPush
	PushApprovalApproved = defaultmfa.PushApprovalApproved
	PushApprovalDenied   = defaultmfa.PushApprovalDenied
	PushApprovalPending  = defaultmfa.PushApprovalPending
)

var (
	ErrMFAMethodConflict           = defaultmfa.ErrMFAMethodConflict
	ErrMFANoProviders              = defaultmfa.ErrMFANoProviders
	ErrMFAUnknownMethod            = defaultmfa.ErrMFAUnknownMethod
	ErrPushApprovalDenied          = defaultmfa.ErrPushApprovalDenied
	ErrPushApprovalInvalid         = defaultmfa.ErrPushApprovalInvalid
	ErrPushApprovalNotFound        = defaultmfa.ErrPushApprovalNotFound
	ErrPushApprovalResolved        = defaultmfa.ErrPushApprovalResolved
	ErrPushApprovalTimeout         = defaultmfa.ErrPushApprovalTimeout
	ErrPushMissingApprovalID       = defaultmfa.ErrPushMissingApprovalID
	ErrPushMissingSubject          = defaultmfa.ErrPushMissingSubject
	ErrPushSubjectMismatch         = defaultmfa.ErrPushSubjectMismatch
	ErrPushUnsupportedMethod       = defaultmfa.ErrPushUnsupportedMethod
	NewCompositeMFAEnrollmentStore = defaultmfa.NewCompositeMFAEnrollmentStore
	NewHTTPWebhookPushTransport    = defaultmfa.NewHTTPWebhookPushTransport
	NewMemoryMFAChallengeStore     = defaultmfa.NewMemoryMFAChallengeStore
	NewMemoryMFAEnrollmentStore    = defaultmfa.NewMemoryMFAEnrollmentStore
	NewMemoryPushApprovalStore     = defaultmfa.NewMemoryPushApprovalStore
	NewMemoryTOTPEnrollmentStore   = defaultmfa.NewMemoryTOTPEnrollmentStore
	NewMultiMFAProvider            = defaultmfa.NewMultiMFAProvider
	NewPushMFAProvider             = defaultmfa.NewPushMFAProvider
	WithPushChannelNotify          = defaultmfa.WithPushChannelNotify
	WithPushMaxWait                = defaultmfa.WithPushMaxWait
	WithPushPollInterval           = defaultmfa.WithPushPollInterval
	WithPushWebhookBearerToken     = defaultmfa.WithPushWebhookBearerToken
	WithPushWebhookClient          = defaultmfa.WithPushWebhookClient
	WithPushWebhookHeader          = defaultmfa.WithPushWebhookHeader
	WithPushWebhookRetry           = defaultmfa.WithPushWebhookRetry
)
